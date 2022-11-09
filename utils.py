#!/usr/bin/env python3.9

__AUTHOR__ = 'Pascal Imthurn'
__VERSION__ = "1.1 October 2022"

"""
Downloader for files

Install dependencies with:
pip install -r requirements.txt
"""

import os.path
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import json
import pandas as pd
from docx import Document

class utils(object):
    def __init__(self, name, url):
        self.name = name
        self.url = url
    
    def _file_exists (self):
        return os.path.exists(self.name)
    
    def _write_file (self, file_contents, type):
        if type == 'xls' or type == 'doc':
            with open(self.name, "wb") as file:
                file.write(file_contents.content)
        else:
            with open(self.name, "w", encoding='utf-8') as file:
                file.write(file_contents)
        
    def _download_and_save(self, type):
        r = requests.get(self.url)
        if type == 'xls' or type == 'doc':
            self._write_file(r, type)
        else:
            self._write_file(r.text, type)
    
    def read_file(self):
        if  not self._file_exists():
            self._download_and_save('json')
        f = open(self.name,'r')
        return f.read()

    def read_txt_file(self):
        if  self._file_exists():
            #f = open(self.name,'r')
            #return f.read()
            data = {}
            with open(self.name,'r') as f:
                for line in f:
                    line = line.strip()
                    (key, val) = line.split(';')
                    data[key] = val
            return data

    def get_excel(self):
        if not self._file_exists():
            self._download_and_save('xls')
        data = pd.read_excel(self.name)
        df = pd.DataFrame(data, columns=['control ID', 'control name', 'mapping type', 'technique ID', 'technique name'])
        df_json = df.to_json(orient="records")
        parsed = json.loads(df_json)
        return parsed

    def get_excel_csf(self):
        if not self._file_exists():
            self._download_and_save('xls')
        data = pd.read_excel(self.name, sheet_name='CSF to SP 800-53r5', header=1)
        df = pd.DataFrame(data, columns=['Function', 'Category', 'Subcategory', 'NIST SP 800-53, Revision 5 Control'])
        # Handle merged cells
        df = df.fillna(method='ffill')
        # Limit the output
        df_short = df.loc[0:107]
        # JSON
        df_json = df_short.to_json(orient="records")
        parsed = json.loads(df_json)
        return parsed

    def get_tsv(self):
        if not self._file_exists():
            self._download_and_save('json')
        data = pd.read_csv(self.name, sep="\t")
        df = pd.DataFrame(data)
        df_json = df.to_json(orient="records")
        parsed = json.loads(df_json)
        return parsed

    def get_json(self):
        if not self._file_exists():
            self._download_and_save('json')
        data = pd.read_json(self.name)
        df = pd.DataFrame(data)
        return df

    def get_table(self, htmlclass):
        tables = pd.read_html(self.url, attrs = {'class' : htmlclass})
        if len(tables) != 1:
            return False
        else:
            df = pd.DataFrame(tables[0])
            df_json = df.to_json(orient="records")
            parsed = json.loads(df_json)
            return parsed

    def get_word(self, table_no, header_no):
        if not self._file_exists():
            self._download_and_save('doc')
        document = Document(self.name)
        df = self._read_docx(document, table_no, header_no)
        df_json = df.to_json(orient="records")
        parsed = json.loads(df_json)
        return parsed
        #return(df)

    def _read_docx(self, document, table_no=1, header_no=1):
        table = document.tables[table_no-1]
        data = [[cell.text for cell in row.cells] for row in table.rows]
        df = pd.DataFrame(data)
        if header_no == 1 and table_no == 1:
            # Table 1 has shared column header
            df.columns = pd.MultiIndex.from_product([['Control ID'], df.columns])
        elif header_no == 1 and table_no == 2:
            df = df.rename(columns=df.iloc[0]).drop(df.index[0]).reset_index(drop=True)
        else:
            print('Not handling headers with more than one header')
            df = pd.DataFrame()
        return df
