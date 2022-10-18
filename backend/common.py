import json,os

os.chdir(os.path.dirname(os.path.realpath(__file__)))

def common():
    with open('./conf/conf.json', 'r') as f:
        conf = json.load(f)
    return conf