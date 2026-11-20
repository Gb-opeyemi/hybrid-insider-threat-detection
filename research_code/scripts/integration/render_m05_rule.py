"""Render a new local M05 XML copy; never deploy or overwrite a rule file."""
import argparse
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from src.lab_config import load_lab_config


def render(config,template,output):
    output=Path(output)
    if output.exists():raise ValueError('Use a new output XML path; no overwrite')
    tree=ET.parse(template)
    fields=tree.findall('.//field[@name="win.eventdata.commandLine"]')
    if len(fields)!=1:raise ValueError('Expected exactly one M05 destination predicate')
    fields[0].text='(?i)'+re.escape(load_lab_config(config)['m05_destination'])
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open('x',encoding='utf-8') as handle:tree.write(handle,encoding='unicode')


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config',type=Path,required=True)
    p.add_argument('--template',type=Path,default=ROOT/'wazuh/rules/thesis_m05_rules.xml')
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args(argv);render(a.config,a.template,a.output)


if __name__=='__main__':main()
