# Skydive & SFC 

The UI of skydive has been modified to graphically indicate that an Service Function Chaining mechanism is used.

## How to use

* Create a Capture
* Make sure that its name contains the term 'SFC' and aditionally provide
    * the string 'DPI' if the SFC is a deep package inspection
    * the string 'Firewall' if the SFC has a firewall role/function.

## Implementation details

Two main changes:
* The capture at server side (flow/ondemand/server/server.go) is also passing the CaptureName variable in the metadata of each node where the capture is active.
* The script the implements visualisation of captures (statics/js/skydive.js) checks the metadata of the node (CaptureName variable, see isSFC function) everytime there is an  update on the graph. If the SFC string is present then the node is marked as part of an SFC. The script then checks for the strings DPI for applying the dpi.png image or Firewall for applying the shield.png image. If none of the two is provided the sfc.png image will be used for the marking
