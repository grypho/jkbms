#!/usr/bin/python3
#
#

import paho.mqtt.publish as publish
def publishMqtt(msgData, format='influx2', broker=None, tag=''):
    return {'topic': tag, 'payload': msgData}

