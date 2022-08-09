#the more things change, the more they stay the same ;)
#if this looks familiar, it is! welcome back, good luck, have fun
import io
import os
import random
import base64
import json
from flask import Flask, jsonify, request, render_template, session
from flask_kvsession import KVSessionExtension
import numpy as np

from sqlalchemy import create_engine, MetaData
from simplekv.db.sql import SQLAlchemyStore
from datetime import timedelta

from werkzeug.utils import secure_filename
from werkzeug.exceptions import HTTPException
from PIL import Image
import imagehash

from torchvision.models import efficientnet_b0
import torchvision.transforms as transforms
import torchvision 
import torch.nn as nn
import torch

# Use environment variable if it exists
FLAG = os.environ.get("FLAG", "uiuctf{fake_flag}")
MIN_LEVEL = 50
SESSION_MINUTES = 5
MUST_REPEAT_CAPTCHA = True
HASH_DIFFERENCE = 4 # how different the imagehash is

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(64)

# Store local session
engine = create_engine('sqlite:////tmp/sessions.db')
metadata = MetaData(bind=engine)
store = SQLAlchemyStore(engine, metadata, 'kvsession_table')
metadata.create_all()
kvsession_extension = KVSessionExtension(store, app)

app.permanent_session_lifetime = timedelta(minutes=SESSION_MINUTES)

# ------------------ Model goes here ⬇------------------ #
classes = ['plane', 'car', 'bird', 'cat', 'deer', 'dog', 'frog', 'horse', 'ship', 'truck']
device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")

model = secret_model()
model.load_state_dict(torch.load("../models/model.pth", map_location = device))
model = model.to(device)
model.eval()

image_set = torchvision.datasets.CIFAR10(root='./static/images', train=False, download=True)
# ------------------ Model goes here ------------------ #

# Get a random image and show it to the user
def gen_img():
    label = 0
    curr_image, label = image_set[random.randint(1, len(image_set))] 
    resize_images = transforms.Compose([transforms.Resize(256),
                        transforms.CenterCrop(224)])
    curr_image = resize_images(curr_image)

    buffered = io.BytesIO()
    curr_image.save(buffered, format='png')
    return base64.b64encode(buffered.getvalue()).decode('utf-8'), label

# Transform image to normalize into model's bounds
def transform_image(image_bytes):
    my_transforms = transforms.Compose([
                        transforms.ToTensor(),
                        transforms.Normalize(
                            [0.485, 0.456, 0.406],
                            [0.229, 0.224, 0.225])])
    image = Image.open(io.BytesIO(image_bytes))
    return my_transforms(image).unsqueeze(0)


def tensor_to_image(tensor):
    tensor = tensor.detach().squeeze().numpy()
    tensor = tensor.transpose(1, 2, 0)
    tensor = (tensor * 255).astype(np.uint8)
    return Image.fromarray(tensor)

def image_to_tensor(img):
    tensor = np.array(img).astype(np.float32) / 255.0
    tensor = tensor.transpose(2, 0, 1)
    tensor = tensor[None, :, :, :] 
    return torch.tensor(tensor, requires_grad=True)

def bytes_to_image(img_data):
    import tempfile
    with tempfile.NamedTemporaryFile(suffix='.png') as tmp:
        tmp.write(img_data)
        tmp.flush()
        return Image.open(tmp.name)

def get_prediction(image_bytes, model, curr_image = None):
    inputs = transform_image(image_bytes=image_bytes)
    outputs = model(inputs)
    preds = torch.argmax(outputs, 1)
    original = Image.open(io.BytesIO(base64.b64decode(curr_image)))

    input_image = Image.open(io.BytesIO(image_bytes))
    hash_orig = imagehash.average_hash(original)
    hash_input = imagehash.average_hash(input_image)

    if hash_orig - hash_input < HASH_DIFFERENCE:
        return classes[preds]
    else:
        return "IMAGE WAS TOO DIFFERENT"

# Function that takes care of the website's repeated image generation and edge conditions
@app.route('/', methods=['GET', 'POST'])
def index():

    response = None
    img = None
    regen_image = session.get('img') is None

    if session.get('level') is None:
        session['level'] = 0
        session['yolo'] = 0
        session.permanent = True
    
    if request.method == 'POST' and 'img' in session:
        file = request.files['file']
        img_bytes = file.read()
        
        image = bytes_to_image(img_bytes)
        (width, height) = image.size 
        depth = len(image.getbands())

        if width != 224 or height != 224 or depth != 3:
            response = f"Invalid image shape. Expecting 224 x 224 with 3 channels, got {width} x {height} with {depth} channels"
        else:   
            pred = get_prediction(image_bytes=img_bytes, model = model, curr_image = session['img'])
            regen_image = True
            if pred != session['label'] and pred != 'no':
                response = "this {} looks like a {}. must not be from our gallery!".format(session['label'], pred)
                session['level'] += 1
            else: 
                response = "our art!! stop, thief!"
                session['yolo'] += 1
               
            if session['yolo'] > 3:
                session['yolo'] = 0
                session['level'] = 0
                response = "you have to move to escape the consequences of your art crimes. try again!"

    if session['level'] >= MIN_LEVEL:
        response = FLAG
    elif response is None:
        response = "you've managed to steal %d paintings. maybe one more will be enough!" % session['level']

    if regen_image or not MUST_REPEAT_CAPTCHA:
        img, label = gen_img()
        session['img'] = img
        session['label'] = classes[label]
    else:
        img = session['img']

    return render_template('index.html', response = response, b64png = img)

@app.errorhandler(RuntimeError)
def error_handler(e):
    return "haha lol something broke" 

if __name__ == '__main__': 
    app.run(host='0.0.0.0', port=1337)