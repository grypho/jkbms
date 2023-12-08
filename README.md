# JK BMS Inquiry #

This project originates from https://github.com/jblance/jkbms which has been moved into the mpp-solar codebase see https://github.com/jblance/mpp-solar .

Nevertheless the mpp-solar project has some shortcomings if a continuous monitoring with an update rate less than 60 seconds is needed.

This project connects to the BMS and keeps the connection until a certain number of data records (typically in an 1s interval) are received. Every data record is sent using MQTT.
