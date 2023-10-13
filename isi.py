import argparse
from genericpath import exists
import os
import shutil
from socket import timeout
import subprocess
import json
import time
from time import sleep

defult_file = ".isi"
defult_json = ".isi.json"
defult_track = ".isi.track"

global isi_path
global json_path
global track_path

isi_path = defult_file
isi_json = defult_json
isi_track = defult_track

global log_file

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("-f", dest="input",
                   help="Input", required=False)
    p.add_argument("-o", dest="fuzzer", help="Fuzzer output Directory", required=False)
    p.add_argument("cmd", nargs="+",
                   help="Command to execute: use @@ to denote a file")
    p.add_argument("-t", dest="timeout",
                   help="Timeout for structure inference", type=int, required=True)
    p.add_argument("-l", dest="log_file", help="Log file", required=True)
    return p.parse_args()


class Chunk:
    def __init__(self, id, start, end, next, prev, parent, child):
        self.id = id
        self.start = start
        self.end = end
        self.next = next
        self.prev = prev
        self.parent = parent
        self.child = child

    def dump_chunk(self):
        print("##parent start = %d and end = %d", self.start, self.end)
        if self.child:
            print("==============following are childs=============")
        child = self.child
        while child:
            child.dump_chunk()
            child = child.next
        if self.child:
            print("==============child end=============")

    def rel2abs(self):
        child = self.child
        while child:
            child.start = child.start + child.parent.start
            child.end = child.end + child.parent.start
            child.rel2abs()
            child = child.next

    def check(self):
        chunk = self
        while chunk:
            if chunk.start > chunk.end:
                print("[DEBUG] chunk " + chunk.id +
                      " start > chunk " + chunk.id + " end")
                return False
            if chunk.parent:
                if chunk.end > chunk.parent.end:
                    print("[DEBUG] chunk " + chunk.id +
                          " end > chunk.parent " + chunk.parent.id + " end")
                    return False
            if chunk.child:
                if chunk.child.check() is False:
                    return False
            chunk = chunk.next
        return True
    
    def adjust_chunk(self, thres):
        iter = self
        while iter:
            next = iter.next
            if iter.end - iter.start == thres:
                iter.child = None
            if iter.end - iter.start == 1:
                #Delete this node
                if iter.prev and iter.next:
                    iter.prev.next = iter.next
                    iter.next.prev = iter.prev
                elif iter.prev:
                    iter.prev.next = None
                elif iter.next:
                    iter.next.prev = None
                    iter.parent.child = iter.next
            if iter.child:
                iter.child.adjust_chunk(thres)
            iter = iter.next
    
    def delete_field(self, input_track):
        iter = self
        while iter:
            if iter.id in input_track:
                iter.child = None
            if iter.child:
                iter.child.delete_field(input_track)
            iter = iter.next
    
    
    def to_json_data(self):
        structure_info = {}
        data = json.loads(json.dumps(structure_info))
        iter = self
        while iter:
            node = {'start': iter.start, 'end': iter.end}
            data[iter.id] = node
            if iter.child:
                data[iter.id]["child"] = iter.child.to_json_data()
            iter = iter.next
        return data


    def to_json(self):
        data = self.to_json_data()
        structure = json.dumps(data, indent=4, ensure_ascii=False)
        return structure

def get_shell(cmd, input):
    global isi_path
    input_path = os.path.abspath(input)
    shutil.copy(input_path, isi_path)
    li = [isi_path if i == "@@" else i for i in cmd]
    shell = " ".join(str(i) for i in li)
    return shell

def gen_cmd(cmd, timeout, input):
    shell = []
    if timeout:
        shell += ["timeout", "-k", str(5), str(timeout)]
    
    global isi_path
    input_path = os.path.abspath(input)
    shutil.copy(input_path, isi_path)
    li = [isi_path if i == "@@" else i for i in cmd]
    shell += li
    return shell

def get_start(item):
    return item.start

def get_child_list(childs):
    child_list = []
    for key in childs.keys():
        item = childs[key]
        child = Chunk(key, item["start"], item["end"], None, None, None, None)
        # print(child.start)
        if "child" in item:
            dchild_list = get_child_list(item["child"])
            dchild_list.sort(key=get_start)
            child.child = dchild_list[0]
            for dchild in dchild_list:
                dchild.parent = child
            tmp = dchild_list[0]
            for i in range(1, len(dchild_list)):
                dchild = dchild_list[i]
                tmp.next = dchild
                dchild.prev = tmp
                tmp = dchild
        child_list.append(child)
    return child_list


def log(message):
    with open(log_file, "a") as log:
        log.write(message)
        log.write("\n")

def check_json(json_path):
    json_legal = False
    try:
        with open(json_path, "r") as f:
            input_json = json.load(f)
            root = get_child_list(input_json)[0]
            if not root.check():
                json_legal = False
            else:
                json_legal = True
    except:
        json_legal = False
    return json_legal

def set_isi_path(input):
    global isi_path, isi_json, isi_track
    input_path = os.path.abspath(input)
    par_dir = os.path.dirname(input_path)
    isi_path = os.path.join(par_dir, defult_file)
    isi_json = os.path.join(par_dir, defult_json)
    isi_track = os.path.join(par_dir, defult_track)
    if os.path.exists(isi_path):
        os.remove(isi_path)
    if os.path.exists(isi_json):
        os.remove(isi_json)
    if os.path.exists(isi_track):
        os.remove(isi_track)

def save_result(input):
    input_path = os.path.abspath(input)
    input_name = os.path.basename(input)
    par_dir = os.path.dirname(input_path)
    input_json = os.path.join(par_dir, input_name + ".json")
    input_track = os.path.join(par_dir, input_name + ".track")
    shutil.copy(isi_json, input_json)
    shutil.copy(isi_track, input_track)
    adjust_structure(input_json, input_track)

def rm_guessed(seed):
    seed_name = os.path.basename(seed)
    par_dir = os.path.dirname(os.path.abspath(seed))
    seed_json = os.path.join(par_dir, seed_name + ".json")
    seed_track = os.path.join(par_dir, seed_name + ".track")
    if os.path.exists(seed_json):
        os.remove(seed_json)
    if os.path.exists(seed_track):
        os.remove(seed_track)

def adjust_structure(json_path, track_path):
    structure = ""
    try:
        with open(json_path, "r") as json_file:
            input_json = json.load(json_file)
            root = get_child_list(input_json)[0]
            root.adjust_chunk(4)
            structure = root.to_json()
    except:
        return False

    try:
        with open(json_path, "w") as f:
            f.write(structure)
    except:
        return False

    try:
        with open(json_path, "r") as json_file:
            with open(track_path, "r") as track_file:
                input_json = json.load(json_file)
                root = get_child_list(input_json)[0]
                root.adjust_chunk(4)
                input_track = json.load(track_file)
                root.delete_field(input_track)
                structure = root.to_json()
    except:
        return False

    try:
        with open(json_path, "w") as f:
            f.write(structure)
    except:
        return False

def infer_strcuture(input, cmd, timeout):
    set_isi_path(input)
    shell = gen_cmd(cmd, timeout, input)
    print("###Infer " + input + "###")
    print(" ".join(shell))
    start_time = time.time()
    proc = subprocess.Popen(shell, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    end_time = time.time()
    json_legal = check_json(isi_json)
    msg = "Infer file: " + input + " \n" + "Infer time: " + str(end_time - start_time) + "\n" + "Return code: " + str(proc.returncode) + "\n" + "Json legel: " + str(json_legal) + "\n"
    log(msg)
    if json_legal:
        save_result(input)
    
    return json_legal

def handle_fuzzer_out(output, cmd, timeout):
    fuzzer_queue = os.path.join(output, "queue")
    infer_dir = os.path.join(output, "structure")
    # if os.path.exists(infer_dir):
    #     shutil.rmtree(infer_dir)
    # os.mkdir(infer_dir)
    if not os.path.exists(infer_dir):
        os.mkdir(infer_dir)

    processed = []
    while True:
        seeds = os.listdir(fuzzer_queue)
        for seed in seeds:
            if seed == ".state" or "json" in seed or "track" in seed:
                continue
            if processed.count(seed):
                continue
            processed.append(seed)

            seed_path = os.path.join(fuzzer_queue, seed)
            shutil.copy(seed_path, infer_dir)

            input_path = os.path.join(infer_dir, seed)

            json_legel = infer_strcuture(input_path, cmd, timeout)

            if json_legel:
                rm_guessed(seed_path)
            
            if os.path.exists(input_path):
                os.remove(input_path)
        print("###Wait 30s for new files###")
        sleep(30)

def main():
    global log_file
    args = parse_args()
    log_file = args.log_file
    if not args.fuzzer and not args.input:
        print("set -f or -o")
        exit()
    cmd = args.cmd
    timeout = args.timeout

    if args.fuzzer:
        handle_fuzzer_out(args.fuzzer, cmd, timeout)

    if args.input:
        infer_strcuture(args.input, cmd, timeout)

if __name__ == "__main__":
    main()
