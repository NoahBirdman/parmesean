import json
from typing import Dict, Any, Optional, List, Tuple
import os 
import struct
import re
from datetime import datetime

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DEVICES_DIR = os.path.join(CURRENT_DIR, "devices")
SETTINGS_FILE = os.path.join(CURRENT_DIR, "settings.json")
OUT_DIR = os.path.join(CURRENT_DIR, "output")
IN_FILE = os.path.join(CURRENT_DIR,"output\\20251113_170222.txt")

DBG_NONE = 0
DBG_MIN = 1
DBG_MAX = 2

NONE = ""
HLINE = "\x1b[37m"
RED = "\x1b[31m"
GREEN = "\x1b[32m"
YELLOW = "\x1b[33m"
BLUE = "\x1b[34m"
MAGENTA = "\x1b[35m"
CYAN = "\x1b[36m"
WHITE = "\x1b[37m"
BRED = "\x1b[91m"
BGREEN = "\x1b[92m"
BYELLOW = "\x1b[93m"
BBLUE = "\x1b[94m"
BMAGENTA = "\x1b[95m"
BCYAN = "\x1b[96m"
BWHITE = "\x1b[97m"
ENDC= "\033[0m"
# data_pattern = re.compile(r"0x([0-9a-fA-F]{2}) ")
# addr_pattern = re.compile(r"\[(0x[0-9a-fA-F]{2})([RrWw]) ([-+])")

# Generic pattern:
#   0xAAW or 0xAAR
#   followed by zero or more " + 0xDD" data bytes
tr_pattern = re.compile(
    r"\[(?P<addr>0x[0-9A-Fa-f]{2})(?P<rw>[WR])(?P<fack>[+-])(0x(?P<data>([0-9A-Fa-f]{2}))(?P<lack>[+-]))*"
)  
data_pattern = re.compile(
    r"0x(?P<data>[a-fA-F0-9]{2})[-+]"
)
#     r"[+-](?P<data>(0x[0-9A-Fa-f]{2})*)"
#Dirty hack to make the JSON colors easy
COLOR = {
    "HLINE": HLINE,
    "RED" : RED,
    "GREEN" : GREEN,
    "YELLOW" : YELLOW,
    "BLUE" : BLUE,
    "MAGENTA" : MAGENTA,
    "CYAN" : CYAN,
    "WHITE" : WHITE,
    "BRED" : BRED,
    "BGREEN" : BGREEN,
    "BYELLOW" : BYELLOW,
    "BBLUE" : BBLUE,
    "BMAGENTA" : BMAGENTA,
    "BCYAN" : BCYAN,
    "BWHITE" : BWHITE,
    "ENDC": ENDC,
}



class i2c_device:
    def __init__(self, name: str, addr: str, desc: str, cmd_length: int, json_path: os.path, debug: int, color: str):
        self.addr = addr
        self.page_addr = None #Stores the current page address. Use the page format commands to change this 
        self.name = name
        self.desc = desc # Device Description
        self.path = json_path
        self.regs = None
        self.debug = debug
        self.color = COLOR["WHITE"]
        self.cmd_length = cmd_length
        self.last_reg = "0x00" # Stores the lest register written to. Works similar to page_addr, if we get a read without a write, return the last known register

        try:
            self.color = COLOR[color]
        except:
            self.printc(f"{color} not found in list. Using Default", DBG_MIN, self.color)

        
        self.printc_line_msg(f"Creating Device: {self.name} @ {self.addr} Debug: {self.debug}", DBG_MIN, self.color)
        if self.path != "":
            try:
                self.printc(f"Opening device settings at: {self.path}", DBG_MAX, self.color)
                with open(self.path, 'r', encoding='utf-8') as f:
                    self.regs = json.load(f)
                    
                    # Count number of registers per page

                    if self.debug >= DBG_MIN:
                        num_pages = len(self.regs)
                        self.printc(f"Num Pages: {num_pages}", DBG_MIN, self.color)
                        
                        for page in self.regs:
                            num_regs = len(self.regs[page])
                            self.printc(f"{self.name} Page {page} has {num_regs}", DBG_MIN, self.color)
                            self.printc(f"Page {page} Register List:", DBG_MAX, self.color)
                            for addr in self.regs[page]:

                                name = self.regs[page][addr]["name"]
                                self.printc(f"     {addr} {name}", DBG_MAX, self.color)
                                # print(f"{self.regs[reg]}")
                    
                    self.page_addr = next(iter(self.regs))
                    self.printc(f"Default Page: {self.page_addr}", DBG_MIN, self.color)

            except Exception as e:
                self.printc(f"Json Read Error: {self.path}. Using default parser", DBG_NONE, self.color)
                print(f"Exception: {e}")
                return None
            
            
        else: 
            self.printc(f"No JSON data provided for ({self.name})", DBG_MIN, self.color)
            self.page_addr = '0x00'
        

    def parse(self, rw: str, data: str, fack: str, lack:str):
        rw = rw
        reg = ""
        reg_name = ""
        result = {
            'addr' : self.addr,
            'name' : self.name,
            'reg' : "NO DATA",
            'reg_name' : "",
            'data' : data,
            'rw' : rw,
            "fack" : fack,
            "lack" : lack,
            "color" : self.color,
            "result" : data,
            "raw" : data
        }
        #return right away if no data
        if len(data) < 4:
            self.printc(f"{self.name}({self.addr}) {rw} ({fack}): (NO DATA) ", DBG_MIN, self.color)
            return result


        # Check for Write  and data is at least 0xAA - store the first register as the command
        if rw == 'W':
            reg = data[0:4]
            self.last_reg = reg # Update register 
            data = "" if len(data) == 4 else '0x' + data[4:] 
        else:
            reg = self.last_reg



        # Look for a valid register name in the JSON
        try:
            reg_name = self.regs[self.page_addr].get(reg)["name"]
        except:
            #Use the hex string for name if no info available
            self.printc(f"Reg not found: {reg}", DBG_MIN, self.color)
                    # Update results with the parsed command
            result['reg'] = reg
            result['reg_name'] = ""
            if data is None:
                data = "NO DATA"
            result['result'] = f"{data}"
            result['data'] = data
            return result

        self.printc("Register Conversion", DBG_MAX, self.color)
        self.printc(f"{self.name}({self.addr}) {rw}:({reg}) {reg_name} {data}", DBG_MIN, self.color)     
        #run this when transaction is complete to do any unit conversion
        output = f"({reg}) {reg_name} {data}"

        try:
            type = self.regs[self.page_addr][reg]["format"].upper()
            self.printc(f"Reg Type: {type}", DBG_MAX, self.color)
        except:
            self.printc(f"No type data available for {reg}", DBG_MIN, self.color)

        try: 
            units = self.regs[self.page_addr][reg]["units"] if self.regs[self.page_addr][reg]["units"] != "NaN" else ""
        except:
            self.printc(f"No Units for: {reg}", DBG_MAX, self.color)
            units = ""

        # No data - Just a command
        if len(data) == 0:
            conv = ""
        #Normal MX+B fit + Units
        elif type == "LINEAR":
            signed = True if self.regs[self.page_addr][reg]["signed"] == "True" else False
            byteorder = self.regs[self.page_addr][reg]["endian"] #Little or big
            data_to_conv = data
            if byteorder == 'little':
                data_to_conv = data[0:2] + data[3:4] + data[2:3]

            conv = int(data_to_conv, 16)
            conv = self.regs[self.page_addr][reg]["slope"] * conv + self.regs[self.page_addr][reg]["offset"]
            self.printc(f"Byte > Float : {conv}", DBG_MIN, self.color)

            
        elif type == "REG":
            # data = data[2:]
            length = 16
            temp = int(data, 16)
            conv = f"0b{temp:0>16b}"


        elif type == "L16":
            # M * 2^-12
            # b'\x5B\x34'  = 5.7 in L16
            # byteorder = self.regs[reg]["endian"] #Little or big
            byte_data = '0x5B34'
            # byte_data = data[:2] + data[4:6] + data[2:4]
            test_output = int(byte_data, 16) * pow(2, -12)     
            self.printc(f"Test Float (0x5B34) > (5.7): {test_output}", DBG_MAX, self.color)   

            byte_data = '0x1133'
            # byte_data = data[:2] + data[4:6] + data[2:4]
            test_output = int(byte_data, 16) * pow(2, -12)    
            self.printc(f"Test Float (0x1133) > (1.075): {test_output}", DBG_MAX, self.color)  
            byte_data = '0x3EA8'
            byte_data = data[:2] + data[4:6] + data[2:4]
            test_output = int(byte_data, 16) * pow(2, -12)    
            self.printc(f"Test Float (0x3EA8) > (0.979): {test_output}", DBG_MAX, self.color)  
            
            # byte_data = data[:2] + data[4:6] + data[2:4]
            byte_data = byte_data = data[:2] + data[4:6] + data[2:4]
            conv = int(byte_data, 16) * pow(2, -12)    

            self.printc(f"Byte > L16 {byte_data} : {conv}", DBG_MIN, self.color)
            
        
        elif type == "L11":
            # b'\xDA\x80'  = 20 IN L11
            #Test data
            byte_data = "0xDA80"
            val_u16 = int(byte_data, 16)
            mantissa = val_u16 & 0x07FF #Mask the lower 11 bits
            exp = (val_u16 >> 11) & 0x1F

            if mantissa & 0x0400: #Signed bit - Convert 2s complement
                mantissa -= 0x0800

            if exp & 0x10: #Check 5th bit for sign
                exp -= 0x20

            conv = mantissa * (2**exp)
            self.printc(f"TEST L11: 0xDA80 ({bin(0xda80)}) > 20", DBG_MIN, self.color)
            self.printc(f"TEST Man: {mantissa}, Exp: {exp}, conv: {conv}", DBG_MAX, self.color)

            # swap the bytes around for little endian
            byte_data = data[:2] + data[4:6] + data[2:4]
            val_u16 = int(byte_data, 16)
            mantissa = val_u16 & 0x07FF #Mask the lower 11 bits
            exp = (val_u16 >> 11) & 0x1F

            if mantissa & 0x0400: #Signed bit - Convert 2s complement
                mantissa -= 0x0800

            if exp & 0x10: #Check 5th bit for sign
                exp -= 0x20

            conv = mantissa * (2**exp)
            # b'\xCAA6' = 5.297 in L11 
            self.printc(f"L11: {byte_data} ({bin(val_u16)})", DBG_MIN, self.color)
            self.printc(f"Man: {mantissa}, Exp: {exp}, conv: {conv}", DBG_MIN, self.color)


        elif type == "ASC":
            conv = data.decode('utf-8')
        
        elif type == "BIN":
            conv = ''.join(f'{byte:08b}' for byte in data)

        elif type == "HEX":
            conv = data

        elif type == "PAGE": # Change the current page address
            self.printc(f"PAGE COMMAND", DBG_MIN, self.color)
            page_addr = str(int(data[0:4], 16))
            

            if page_addr in self.regs:
                self.printc(f"Current Page Address: {page_addr}", DBG_MIN, self.color)
                self.printc(f"New Page Address: {page_addr}", DBG_MIN, self.color)
                conv = f"New Page Address: {page_addr}"

                self.page_addr = page_addr
            else:
                self.printc(f"No Matching Page Address for: {page_addr}", DBG_NONE, self.color)
                self.printc(f"Current Page Address: {self.page_addr}", DBG_MIN, self.color)
                conv = f"No Matching Page Address for: {page_addr}"

            

        else :
            self.printc(f"Type {type} is not implemented", DBG_NONE)
            conv = data

        output = f"({reg}) {reg_name} {conv}{units}"
        self.printc(f"Output: {output}", DBG_MIN, self.color)
        
        result['reg'] = reg
        result['reg_name'] = reg_name
        result['result'] = f"{conv}{units}"
        return result
    

    #print debug messages based on debug level
    def printc(self, message: str, dbg: int, color: str = None):
        if dbg <= self.debug:
            color = self.color if color is None else color
            print(f"{color}{message}{ENDC}")

    def printc_line(self, dbg: int, color: str):
        if dbg <= self.debug:
            color = self.color if color is None else color
            print(f"{color}--------------------------------------------------{ENDC}")

    def printc_line_msg(self, message: str, dbg: int, color: str = None):
        if dbg <= self.debug:
            num = len(message)
            num_dash = int((50 - num - 2) / 2)
            dashes = '-' * num_dash
            color = self.color if color is None else color
            print(f"{color}{dashes} {message} {dashes}{ENDC}")


class Parmesean():
    def __init__(self, 
                 settings_file: str = SETTINGS_FILE,
                 devices_dir: str = DEVICES_DIR,
                 out_dir: str = OUT_DIR,
                 save_data: bool = False
                 ):
        self.devices = {}
        self.ignore_list = []
        self.debug = False
        self.out_dir = out_dir # Folder to put saved output text files
        self.devices_dir = devices_dir # Folder with JSON device files
        self.settings_file = settings_file # Path to specific json settings file
        self.save_data = save_data
        # TODO: Eventually make this a Saleae setting to change the prefix/suffix
        now = datetime.now()
        timestampe_str = now.strftime("%Y%m%d_%H%M%S")
        self.out_file = os.path.join(self.out_dir, (timestampe_str + ".txt"))

        print("\033c")
        print("\x1b[H\x1b[2J\033[0m")
        print("----------Welcome to Parmesean----------")
        self.load_settings()
       
        # Only save data if we want to. 
        if self.save_data:
            try:
                open(self.out_file, 'w').close()
                print(f"File '{self.out_file}' created successfully and is blank.")
            except OSError as e:
                print(f"Error creating file: {e}")
        
    
    def load_settings(self):
        print(f"Loading Settings: {self.settings_file}")
        try:
            with open(self.settings_file, 'r', encoding='utf-8') as f:
                settings = json.load(f)
        except:
            print(f"Json Read Error: {self.settings_file}")
            exit()

        #Check if settings exists
        if settings is None:
            print("Failed to load settings.")
            exit()

        for s in settings["settings"]:
            #Debug
            if s["name"] == "Debug":
                    debug_int = s["value"] #Save value and then overwrite with new setting
                    if isinstance(debug_int, int):
                        debug = debug_int
                    else:
                        print(f"Error Setting Debug:{debug_int} ")
                        debug = DBG_MAX

                    
                    print(f"Debug: {debug}")

            #Save Settings
            elif s["name"] == "Save New Devices":
                    save_devices = s["value"]
                    print(f"Save Devices: {save_devices}")
                        

            elif s["name"]  == "Ignore Devices":
                    ilist = s["value"]
                    ilist = ilist.replace(" ", "")
                    self.ignore_list = ilist.split(",")                       

                    print(f"Ignore List: {self.ignore_list}")
            elif s["name"] == "Save Output":
                save_output = s["value"]
                print(f"Save Output: {save_output}")


        for d in settings["devices"]:
            json_path = ""
            if d['parser'] != "":
                json_path = os.path.join(self.devices_dir, d["parser"])
                # print(f"Dir:{device_directory}")
                # print(f"Device: {d}")
                # parser = d["parser"]
                # print(f"Parser: {parser}")

            dev = i2c_device(name=d["name"], 
                            addr=d['address'],
                            desc=d["description"],
                            cmd_length=d['cmd_length'],
                            json_path=json_path,
                            debug=d['debug'],
                            color=d["color"])
            # Insert new device at the associated address and check if it was created correctly
            if dev.addr is not None:
                self.devices[dev.addr] = dev

        print("Starting Parmesean with the following devices:")

        for dev in self.devices.values():
            if dev.addr in self.ignore_list:
                dev.printc(f"{dev.name} @ {dev.addr} (IGNORED)", DBG_NONE)
            else:
                dev.printc(f"{dev.name} @ {dev.addr} : {dev.desc}", DBG_NONE)
        print("----------------------------------------------------")


    def parse(self, data: str):
        if self.save_data:
            with open(self.out_file, "a") as f:
                    f.write(f"{data}\n")

        data = line.strip()
        data = data.replace(" ", "")
        rw = "ERROR"
        addr = "ERROR"
        ack = 'ERROR'
        result = {
            'addr' : "",
            'name' : "",
            'reg' : "",
            'reg_name' : "",
            'data' : "",
            'rw' : "",
            "fack" : "",
            "lack" : "",
            "color" : "",
            "result" : "",
            "raw" : "",
            "orig" : data
        }

        result_list = []
        for tr in tr_pattern.finditer(data):

            # Look for the first address message to store the RW token
            # addr_match = addr_pattern.search(data)
            # tr_match = tr_pattern.search(data)
            addr = tr.group("addr")
            rw = tr.group("rw")
            fack = 'ACK' if tr.group("fack") == '+' else 'NACK'
            data_list = data_pattern.findall(tr.group(0))
            lack = tr.group('lack')
            # Format all the valid data together 
            # Otherwise make the parsing string blank
            if data_list is not None:
                data_str = '0x' + "".join(data_list)
            else:
                data_str = ""

            if addr is None:
                self.printc(f"NO ADDRESS FOUND IN {data}", DBG_NONE)
                result['addr'] = "ERROR"
                result['rw'] = "ERROR"
                result['fack'] = "ERROR"
                result['lack'] = "ERROR"
                result_list.append(tr)
                pass
            
            # Check if address should be ignored
            if addr in self.ignore_list:
                self.printc(f"Transaction Ignored: {addr}", DBG_NONE)
                result['addr'] = addr
                result['rw'] = rw
                result['fack'] = fack
                result['lack'] = lack
                result['data'] = data
                result['addr'] = f"{addr}"
                result['result'] = f"(IGNORED)"
                result_list.append(result)
                # Do nothing with the data
                pass

            # Check for address in device list
            elif addr not in self.devices:
                self.printc(f"Creating new device for {addr}", DBG_MIN, GREEN)
                dev = i2c_device(addr=addr, cmd_length=0,desc="", name="", json_path="", debug=self.debug, color=RED)   
                
                if dev is not None:
                    self.devices[addr] = dev
                
            # Check if address was added before using it
            if addr in self.devices:
                # print('Data: ', data)
                result = self.devices[addr].parse(rw, data_str, fack, lack)
                result['orig'] = data
                # self.devices[addr].printc(f"{result['name']}({result['addr']}) {result['rw']} {result['reg_name']}({result['reg']}) {result['result']} ({result['data']})", DBG_MIN, result['color'])
                result_list.append(result)

        # Set result to None if no data is found
        if len(result_list) == 0:
            result_list = None
        return result_list

    #print debug messages based on debug level
    def printc(self, message: str, dbg: int, color: str = None):
        if dbg <= self.debug:
            color = self.color if color is None else color
            print(f"{color}{message}{ENDC}")

    def printc_result(self, result: List, color: str = None):

        self.printc(f"{result['name']}({result['addr']}) {result['rw']} ({result['fack']}) {result['reg_name']}({result['reg']}) {result['result']} ({result['raw']})", DBG_NONE, result['color'])



if __name__ == "__main__":
    parm = Parmesean()
    IN_FILE = os.path.join(CURRENT_DIR,"output\\20251113_170222.txt")

    with open(IN_FILE, 'r') as f:
        print(f"Parsing all data in: {IN_FILE}")
        for line in f:

            ''' Process every frame from the input analyzer and reutrn a full I2C transaction frame'''
            print("----------------------------------------------------")
            result_list = parm.parse(line)
            line = line.strip()
            line= line.replace(" ", "")
            print(line)
            if result_list is not None:
                for r in result_list:
                    parm.printc_result(r, DBG_NONE)
                # self.printc(f"Decoding: {line}", DBG_MAX, color)
                #Stop frame -- return the final frame to the HLA
                # data_pattern = re.compile(r"0x([0-9a-fA-F]{2}) $")
            

            
    
    print(f"Conversion Complete")
    
