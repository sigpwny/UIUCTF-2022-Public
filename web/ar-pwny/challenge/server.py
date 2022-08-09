# coding: utf-8
from flask import Flask, request, send_from_directory, render_template
import hashlib

# https://stackoverflow.com/questions/20646822/how-to-serve-static-files-in-flask
app = Flask(__name__, static_url_path='')

@app.route('/', methods=['GET'])
def main():
    return app.send_static_file('index.html')

if __name__ == '__main__':
    app.run(host="0.0.0.0",port=1337)
