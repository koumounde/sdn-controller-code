# Copyright 2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This file is a modified version of the original project.

"""
This component is for use with the OpenFlow tutorial.

It acts as a simple hub, but can be modified to act like an L2
learning switch.

It's roughly similar to the one Brandon Heller did for NOX.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()



class Tutorial (object):
  """
  A Tutorial object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)
    #core.openflow.addListenerByName("FlowRemoved", _on_FlowRemoved)

    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    self.mac_to_port = {}

    #Has the timeout for the flows expired?
    self.timeout_expired = False

    # Holds the source/destination pairs for which flows have already been created once
    #self.flows_created = {}

  def resend_packet (self, packet_in, out_port):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)


  def act_like_hub (self, packet, packet_in):
    """
    Implement hub-like behavior -- send all packets to all ports besides
    the input port.
    """

    # We want to output to all ports -- we do that using the special
    # OFPP_ALL port as the output port.  (We could have also used
    # OFPP_FLOOD.)
    self.resend_packet(packet_in, of.OFPP_ALL)

    # Note that if we didn't get a valid buffer_id, a slightly better
    # implementation would check that we got the full data before
    # sending it (len(packet_in.data) should be == packet_in.total_len)).


  def act_like_switch (self, packet, event):
    """
    Implement switch-like behavior.
    """
    packet_in = event.ofp

    # Here's some psuedocode to start you off implementing a learning
    # switch.  You'll need to rewrite it as real Python code.
    #log.debug("Incoming packet from " + str(packet.payload.srcip))

    # Learn the port for the source MAC
    input_mac = str(packet.src)
    output_mac = str(packet.dst)
    input_port = event.port

    self.mac_to_port[input_mac] = input_port

    #g.debug("Learned that MAC " + input_mac + " is at port " + str(input_port) )
    #log.debug("Mapping:" + str(self.mac_to_port) + ", input mac: " + input_mac + " output mac:" + output_mac)

    if self.mac_to_port.has_key(output_mac):
      # Send packet out the associated port
      output_port = self.mac_to_port[output_mac]

      #log.debug("Found packet with known MAC " + output_mac +  ", resending it to port " + str(output_port))
      #self.resend_packet(packet_in, output_port)

      # Once you have the above working, try pushing a flow entry
      # instead of resending the packet (comment out the above and
      # uncomment and complete the below.)

      #log.debug("Got packet from " + input_mac + " port " + str(input_port) + ", sending to " + output_mac + " port " + str(output_port))
      # Maybe the log statement should have source/destination/port?

      msg = of.ofp_flow_mod()
      #
      ## Set fields to match received packet
      msg.match = of.ofp_match.from_packet(packet)
      #
      #< Set other fields of flow_mod (timeouts? buffer_id?) >
      msg.buffer_id = packet_in.buffer_id

      #if (input_mac, output_mac) not in self.flows_created.items():
      #< Add an output action, and send -- similar to resend_packet() >
      if not self.timeout_expired:
          msg.actions.append(of.ofp_action_output(port=output_port))
          msg.hard_timeout = 10
          msg.flags = of.OFPFF_SEND_FLOW_REM
          log.debug("Created new flow for " + input_mac + " : " + output_mac + " with flags " + str(msg.flags))

      # We must store the fact that we created a new flow for this source/dest pair
      #self.flows_created[input_mac] = output_mac

      # Finally send the message
      self.connection.send(msg)

    else:
      # Flood the packet out everything but the input port
      # This part looks familiar, right?
      #log.debug("Sending packet everywhere")
      self.resend_packet(packet_in, of.OFPP_ALL)


  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    #packet_in = event.ofp # The actual ofp_packet_in message.

    # Comment out the following line and uncomment the one after
    # when starting the exercise.
    #self.act_like_hub(packet, packet_in)
    #self.act_like_switch(packet, packet_in)
    self.act_like_switch(packet, event)

  def _handle_FlowRemoved(self, event):
    """
    Handles flow removed events from the switch
    """

    if event.hardTimeout:
        log.debug("Flow removed due to hard timeout")
        self.timeout_expired = True

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Tutorial(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
