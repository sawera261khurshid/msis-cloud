import paho.mqtt.client as mqtt
import json
# import streamlit as st
import time
import collections
import csv
import pandas as pd
import numpy as np
import socket
from datetime import date
from datetime import datetime
# import cont_type

HOST='100.104.49.44'
PORT = 1883
def on_connect(client, userdata, flags, rc):
    if rc==0:
        print("Conected to broker")
        machine='airbag-002'
        # machine='ket-pin-5'
        # machine= socket.gethostname()
        client.subscribe(f"smartfactory/message/{machine}/#")
        client.subscribe(f"smartfactory/trigger/{machine}/#")
        client.subscribe(f"smartfactory/control/{machine}/#")
    else:
        print("Coonection failed")

tem_msg=''
tem_trg=''
tem_contrl=''
def on_message(client, userdata, msg):
    global tem_msg
    global tem_trg
    global tem_contrl
    
    machine='airbag-002'
    # machine='ket-pin-5'
    # machine= socket.gethostname()

    #### Date and Time
    today = date.today()
    c = datetime.now()
    current_time = c.strftime('%H:%M:%S')
    print(msg.topic)

    if msg.topic == f'smartfactory/message/{machine}/camera_0':
        tem_msg= str(msg.payload.decode('utf-8'))
        tem_msg= json.loads(tem_msg)
    
    if msg.topic == f'smartfactory/trigger/{machine}/camera_0':
        tem_trg= str(msg.payload.decode('utf-8'))
        tem_trg= json.loads(tem_trg)
    
    if msg.topic == f'smartfactory/control/{machine}/camera_0':
        tem_contrl= str(msg.payload.decode('utf-8'))
        tem_contrl= json.loads(tem_contrl)
    
    if tem_msg and tem_trg and tem_contrl:
        message_handler(tem_msg, tem_trg, tem_contrl, today, current_time)

status_msg_list=[]
status_trg_list=[]
decision_mode=[]
connector_model=[]
day_msg=[]
time_msg=[]
connector_type=[]

def message_handler(tem_msg, tem_trg, tem_contrl,today, current_time):

    ####### Message 
    print(tem_msg["stt"], tem_trg["stt"], current_time)
    # status_msg = tem_msg["stt"]
    # status_msg_list.append(tem_msg["stt"][0])
    # #### Triger 
    # # status_trg = tem_trg["stt"]
    # status_trg_list.append(tem_trg["stt"])
    # # print(f"{status_msg_list} \n{status_arg_list_list}")
    # ###### Final Decision Mode
    # decision_mode.append(tem_contrl["args"]["final_decision_mode"])

    # ######## Template Matching
    # for p_id, p_info in cont_type.connector_type_mode.items():
    #     for key in p_info:
    #         if tem_contrl["args"]["template_matching"]==p_info[key]:
    #             print(f'{p_id}: {key}: {p_info[key]}')
    #             connector_type.append(str(p_id))
    #             connector_model.append(str(key))
    # day_msg.append(today)
    # time_msg.append(current_time)

    # df = pd.DataFrame({'Final Status':status_msg_list, 'Trigger':status_trg_list, 'Desision_Mode': decision_mode, 'Connector Model':connector_model, 'Connector Type':connector_type, 'Date': day_msg, 'Recieving Time': time_msg})
    # # df = pd.DataFrame([status_msg_list,status_arg_list_list], columns=['Final', 'Trigger'])
    # print('This is df: ',df)
    # # Store DataFrame to csv, skipping the index
    # df.to_csv(f"../{date.today()}.csv", index=False)


client = mqtt.Client()
client.on_connect= on_connect
client.on_message = on_message
client.connect(HOST, PORT,60)
# machine='mold-002'
# client.subscribe(f"smartfactory/message/{machine}/#")
# client.subscribe(f"smartfactory/trigger/{machine}/#")
client.loop_forever()

