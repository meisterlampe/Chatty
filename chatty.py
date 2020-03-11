#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import appdaemon.plugins.hass.hassapi as hass
import slixmpp
import slixmpp_omemo

class Chatty(hass.Hass):
    class Command:
        def __init__(self, name, callback):
            self.name = name
            self.callback = callback

    def register_command(self, name, callback):
        self.commands.append(Chatty.Command(name, callback))

    async def initialize(self):
        username = self.args["username"]
        password = self.args["password"]
        self.recipients = self.args["recipients"] # note, this is expected to be an array!

        self.commands = list()

        self.start_xmpp(username, password)

        self.register_service("notify/jabber", self.on_notify_service)
        self.listen_event(self.on_notify_event, "NOTIFY_JABBER")

        self.log("Chatty started.")

        # register commands
        self.mycommands = MyCommands(self)

    def start_xmpp(self, username, password):
        self.log("Starting chatty with username: {}".format(username))
        
        self.xmpp = XMPPconnector(username, password, self)
        self.xmpp.register_plugin('xep_0030') # Service Discovery
        self.xmpp.register_plugin('xep_0004') # Data Forms
        self.xmpp.register_plugin('xep_0060') # PubSub
        self.xmpp.register_plugin('xep_0199') # XMPP Ping
        self.xmpp.register_plugin('xep_0380') # XMPP Ping

        try:
            self.xmpp.register_plugin(
                'xep_0384',
                {
                    'data_dir': "/conf/apps/chatty",
                },
                module=slixmpp_omemo,
            ) # OMEMO
        except (slixmpp_omemo.PluginCouldNotLoad,):
            self.log.exception('And error occured when loading the omemo plugin.')
            self.sys.exit(1)

        self.xmpp.connect()
        #xmpp.process()   ## we are already async        

    def on_notify_service(self, ns, domain, service, data):
        """
        callback for service (from within appdaemon)
        """
        self._on_notify(data["message"])

    def on_notify_event(self, event_name, data, kwargs):
        """
        callback for event (from homeassistant)
        """
        self._on_notify(data["message"])

    def _on_notify(self, message):
        """
        send message to predefined XMPP contacts
        """
        for recipient in self.recipients:
            self.log("Sending '{}' to '{}'".format(message, recipient))
            self.xmpp.send_message_to(recipient, message)

    async def on_incoming_message(self, msgBody, sender):
        self.log("Incoming: '{}', from '{}".format(msgBody, sender))

        # all commands are case insensitive
        msgBody = msgBody.lower()

        # find command, triggered by the incoming message, and run it
        command = Chatty.Command("", None)
        for x in self.commands:
            if msgBody.startswith(x.name) and len(x.name) > len(command.name):
                command = x

        if command.name != "":
            self.log("Running command: {}".format(command.name))
            return await command.callback(msgBody)
        else:
            self.log("Command not found.")
            return "Sorry, but... what?"

        # return an answer to the sender (optional)
        return None

    async def terminate(self):
        self.log("Terminating XMPP session")

        self.xmpp.do_reconnections = False
        self.xmpp.disconnect()

        await self.xmpp.disconnected
        del self.xmpp
                
        self.log("XMPP session terminated.")


    
class XMPPconnector(slixmpp.ClientXMPP):
    eme_ns = 'eu.siacs.conversations.axolotl'

    def __init__(self, jid, password, message_handler):
        slixmpp.ClientXMPP.__init__(self, jid, password)
        self.message_handler = message_handler
        self.log = message_handler.log

        self.do_reconnections = True
        self.is_first_connection = True

        self.add_event_handler("session_start", self.start)
        self.add_event_handler("message", self.on_message)
        self.add_event_handler("disconnected", self.on_disconnect)
        self.add_event_handler("connection_failed", self.on_connection_failure)

    def start(self, event):
        self.log("Connection established.")
        self.send_presence()
        self.get_roster()

        if self.is_first_connection:
            self.is_first_connection = False
        else:
            self.message_handler._on_notify("Reconnected after connection loss.")

    def on_disconnect(self, event):
        if self.do_reconnections:
            self.connect()

    def on_connection_failure(self, event):
        self.log("XMPP connection failed. Try to reconnect in 5min.")
        self.schedule("Reconnect after connection failure", 60*5, self.on_disconnect, event)

    def send_message_to(self, recipient, message):
        try:
            self.send_message(mto=recipient, mbody=message, mtype='chat')
        except slixmpp.xmlstream.xmlstream.NotConnectedError:
            self.log("Message NOT SENT, not connected.")
            ## TODO enqueue message for sending after reconnect
        except:
            self.log("Message NOT SENT, due to unexpected error!")

    async def on_message(self, msg):
        """
        called by slixmpp on incoming XMPP messages
        """

        if msg['type'] in ('chat', 'normal'):

            if self['xep_0384'].is_encrypted(msg):
                await self.on_omemo_message(msg)
            else:
                await self.on_unencrypted_message(msg)

    async def on_omemo_message(self, msg):
        """
        Called to handle incoming omemo encrypted messages
        """
        try:
            allow_untrusted = True
            sender = msg['from']
            encrypted_msg = msg['omemo_encrypted']
            body = self['xep_0384'].decrypt_message(encrypted_msg, sender, allow_untrusted).decode("utf8")
            answer = await self.message_handler.on_incoming_message(body, sender)
            if answer:
                await self.encrypted_reply(msg, answer)
            return None
        except (slixmpp_omemo.MissingOwnKey,):
            # The message is missing our own key, it was not encrypted for
            # us, and we can't decrypt it.
            msg.reply('I can\'t decrypt this message as it is not encrypted for me.').send()
            return None
        except (slixmpp_omemo.NoAvailableSession,) as exn:
            # We received a message from that contained a session that we
            # don't know about (deleted session storage, etc.). We can't
            # decrypt the message, and it's going to be lost.
            # Here, as we need to initiate a new encrypted session, it is
            # best if we send an encrypted message directly. XXX: Is it
            # where we talk about self-healing messages?
            await self.encrypted_reply(
                msg,
                'I can\'t decrypt this message as it uses an encrypted '
                'session I don\'t know about.',
            )
            return None
        # except (slixmpp_omemo.UndecidedException, slixmpp_omemo.UntrustedException) as exn:
        #     # We received a message from an untrusted device. We can
        #     # choose to decrypt the message nonetheless, with the
        #     # `allow_untrusted` flag on the `decrypt_message` call, which
        #     # we will do here. This is only possible for decryption,
        #     # encryption will require us to decide if we trust the device
        #     # or not. Clients _should_ indicate that the message was not
        #     # trusted, or in undecided state, if they decide to decrypt it
        #     # anyway.
        #     await msg.reply("Your device '%s' is not in my trusted devices." % exn.device).send()
            
        #     # We resend, setting the `allow_untrusted` parameter to True.
        #     await self.on_omemo_message(msg, allow_untrusted=True)
        #     return None
        except (slixmpp_omemo.EncryptionPrepareException,):
            # Slixmpp tried its best, but there were errors it couldn't
            # resolve. At this point you should have seen other exceptions
            # and given a chance to resolve them already.
            msg.reply('I was not able to decrypt the message.').send()
            return None
        except (Exception,) as exn:
            msg.reply('An error occured while attempting decryption.\n%r' % exn).send()
            raise

        return None

    async def on_unencrypted_message(self, msg):
        """
        Called to handle incoming unencrypted messages
        """
        answer = await self.message_handler.on_incoming_message(msg["body"], msg["from"])

        if answer:
            try:
                msg.reply(answer).send()
            except slixmpp.xmlstream.xmlstream.NotConnectedError:
                self.log("Reply NOT SENT, not connected.")
                ## TODO enqueue message for sending after reconnect
            except:
                self.log("Reply NOT SENT, due to unexpected error!")

    async def encrypted_reply(self, original_msg, msg_to_send):
        """
        Encrypts the given message and sends it
        """
        recipient = original_msg['from']
        msgType = original_msg['type']
        msg = self.make_message(mto=recipient, mtype=msgType)
        msg['eme']['namespace'] = self.eme_ns
        msg['eme']['name'] = self['xep_0380'].mechanisms[self.eme_ns]

        expect_problems = {}  # type: Optional[Dict[JID, List[int]]]

        while True:
            try:
                # `encrypt_message` excepts the plaintext to be sent, a list of
                # bare JIDs to encrypt to, and optionally a dict of problems to
                # expect per bare JID.
                #
                # Note that this function returns an `<encrypted/>` object,
                # and not a full Message stanza. This combined with the
                # `recipients` parameter that requires for a list of JIDs,
                # allows you to encrypt for 1:1 as well as groupchats (MUC).
                #
                # `expect_problems`: See EncryptionPrepareException handling.
                recipients = [recipient]
                encrypt = await self['xep_0384'].encrypt_message(msg_to_send, recipients, expect_problems)
                msg.append(encrypt)
                return msg.send()
            except slixmpp_omemo.UndecidedException as exn:
                # The library prevents us from sending a message to an
                # untrusted/undecided barejid, so we need to make a decision here.
                # This is where you prompt your user to ask what to do. In
                # this bot we will automatically trust undecided recipients.
                self['xep_0384'].trust(exn.bare_jid, exn.device, exn.ik)
            # TODO: catch NoEligibleDevicesException
            except slixmpp_omemo.EncryptionPrepareException as exn:
                # This exception is being raised when the library has tried
                # all it could and doesn't know what to do anymore. It
                # contains a list of exceptions that the user must resolve, or
                # explicitely ignore via `expect_problems`.
                # TODO: We might need to bail out here if errors are the same?
                for error in exn.errors:
                    if isinstance(error, slixmpp_omemo.MissingBundleException):
                        # We choose to ignore MissingBundleException. It seems
                        # to be somewhat accepted that it's better not to
                        # encrypt for a device if it has problems and encrypt
                        # for the rest, rather than error out. The "faulty"
                        # device won't be able to decrypt and should display a
                        # generic message. The receiving end-user at this
                        # point can bring up the issue if it happens.
                        self.plain_reply(
                            original_msg,
                            'Could not find keys for device "%d" of recipient "%s". Skipping.' %
                            (error.device, error.bare_jid),
                        )
                        jid = slixmpp.JID(error.bare_jid)
                        device_list = expect_problems.setdefault(jid, [])
                        device_list.append(error.device)
            except (slixmpp.exceptions.IqError, slixmpp.exceptions.IqTimeout) as exn:
                self.plain_reply(
                    original_msg,
                    'An error occured while fetching information on a recipient.\n%r' % exn,
                )
                return None
            except Exception as exn:
                await self.plain_reply(
                    original_msg,
                    'An error occured while attempting to encrypt.\n%r' % exn,
                )
                raise

        return None


class MyCommands:
    def __init__(self, chatty):
        """
        extend this class with your own commands
        """
        self.chatty = chatty

        chatty.register_command("help", self.help)

    async def help(self, message):
        return "I'm alive. But I can't really do anything, yet."
