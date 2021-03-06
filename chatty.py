#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import appdaemon.plugins.hass.hassapi as hass
import slixmpp

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

    async def on_incoming_message(self, msg):
        message = msg["body"]
        sender = msg["from"]
        self.log("Incoming: '{}', from '{}".format(message, sender))

        # all commands are case insensitive
        message = message.lower()

        # find command, triggered by the incoming message, and run it
        command = Chatty.Command("", None)
        for x in self.commands:
            if message.startswith(x.name) and len(x.name) > len(command.name):
                command = x

        if command.name != "":
            self.log("Running command: {}".format(command.name))
            return await command.callback(message)
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
            answer = await self.message_handler.on_incoming_message(msg)

            if answer:
                try:
                    msg.reply(answer).send()
                except slixmpp.xmlstream.xmlstream.NotConnectedError:
                    self.log("Reply NOT SENT, not connected.")
                    ## TODO enqueue message for sending after reconnect
                except:
                    self.log("Reply NOT SENT, due to unexpected error!")


class MyCommands:
    def __init__(self, chatty):
        """
        extend this class with your own commands
        """
        self.chatty = chatty

        chatty.register_command("help", self.help)

    async def help(self, message):
        return "I'm alive. But I can't really do anything, yet."

