#!/usr/bin/python3
import base64
import functools
import json
import os
import subprocess
import sys

import utils

import flask_debugtoolbar
import flask_debugtoolbar_mongo

from classes import *
from flask import Flask, abort, jsonify, redirect, render_template, request, session, url_for
from flask_github import GitHub
from flask_mongoengine import MongoEngine

devicefile = "kernels.json"
forceDBUpdate = False

version = subprocess.check_output(["git", "describe", "--always"], cwd=os.path.dirname(os.path.realpath(__file__))).decode('utf-8')
app = Flask(__name__)
app.config.from_pyfile('app.cfg')
app.secret_key = app.config['SECRET_KEY']
if app.secret_key == 'default':
    raise Exception("You need to set the secret key!")

app.jinja_env.auto_reload = True
app.config['TEMPLATES_AUTO_RELOAD'] = True

dir = os.path.dirname(__file__)

with open(os.path.join(dir, devicefile)) as device_file:
    devices = json.load(device_file)

db = MongoEngine(app)
github = GitHub(app)

app.config['DEBUG_TB_PANELS'] = [
    'flask_debugtoolbar.panels.versions.VersionDebugPanel',
    'flask_debugtoolbar.panels.timer.TimerDebugPanel',
    'flask_debugtoolbar.panels.headers.HeaderDebugPanel',
    'flask_debugtoolbar.panels.request_vars.RequestVarsDebugPanel',
    'flask_debugtoolbar.panels.template.TemplateDebugPanel',
    'flask_debugtoolbar.panels.logger.LoggingPanel',
    'flask_debugtoolbar.panels.profiler.ProfilerDebugPanel',
    # Add the MongoDB panel
    'flask_debugtoolbar_mongo.panel.MongoDebugPanel',
]

toolbar = flask_debugtoolbar.DebugToolbarExtension(app)

@app.cli.command()
def update_progress():
    for k in Kernel.objects():
        k.progress = utils.getProgress(k.id)
        k.save()

@app.cli.command()
def update_kernels():
    utils.getKernelTableFromGithub(app)

def logged_in():
    return ('github_token' in session and session['github_token']) or app.config['GITHUB_ORG'] == None

def require_login(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if not logged_in():
            return jsonify({'error': 'not logged in'})
        return f(*args, **kwargs)
    return wrapper

@app.route("/login")
def login():
    if 'github_token' not in session or not session['github_token']:
        return github.authorize(scope="user:email, read:org")
    else:
        return redirect(url_for('index'))
    return response

@app.route('/login/authorized')
@github.authorized_handler
def authorized(access_token):
    next_url = request.args.get('next') or url_for('index')
    if access_token is None:
        return redirect(next_url)
    req = github.raw_request("GET", "user/orgs", access_token=access_token)
    if req.status_code == 200:
        orgs = [x['login'] for x in req.json()]
    if app.config['GITHUB_ORG'] in orgs:
        session['github_token'] = access_token
        return redirect(next_url)
    else:
        return 'Invalid org, {} not in [{}]'.format(app.config['GITHUB_ORG'], ', '.join(orgs))

@app.route("/logout")
def logout():
    session.pop('github_token', None)
    return redirect(url_for('index'))


@github.access_token_getter
def get_github_token():
    return session.get('github_token')

@app.route("/secure")
@require_login
def secure():
    return "logged in"


def error(msg = ""):
    return render_template('error.html', msg=msg)

@app.route("/")
def index():
    kernels = Kernel.objects(deprecated__in=[False, None]).order_by('vendor', 'device')
    return render_template('index.html', kernels=kernels, version=version, authorized=logged_in(),
          needs_auth=app.config['GITHUB_ORG'] != 'none')

@app.route("/deprecated")
def show_deprecated():
    kernels = Kernel.objects(deprecated=True).order_by('vendor', 'device')
    return render_template('index.html', kernels=kernels, version=version, authorized=logged_in(),
          needs_auth=app.config['GITHUB_ORG'] != 'none', deprecated=True)

@app.route("/<string:k>")
def kernel(k):
    try:
        kernel = Kernel.objects.get(repo_name=k)
    except:
        abort(404)
    cves = CVE.objects().order_by('cve_name')
    statuses = {s.id: s.short_id for s in Status.objects()}
    patches = {p.cve: p.status for p in Patches.objects(kernel=kernel.id)}
    patch_status = []
    for c in cves:
      patch_status.append(statuses[patches[c.id]])

    if k in devices:
        devs = devices[k]
    else:
        devs = ['No officially supported devices!']
    return render_template('kernel.html',
                           kernel = kernel,
                           cves = cves,
                           patch_status = patch_status,
                           status_ids = Status.objects(),
                           patches = patches,
                           devices = devs,
                           authorized=logged_in())

@app.route("/status/<string:c>")
def cve_status(c):
    kernels = Kernel.objects(deprecated__in=[False, None]).order_by('vendor', 'device')
    cve = CVE.objects.get(cve_name=c)
    statuses = {s.id: s.short_id for s in Status.objects()}
    patches = {p.kernel: p.status for p in Patches.objects(cve=cve.id)}
    return render_template('status.html',
                           cve_name = c,
                           kernels = kernels,
                           patches = patches,
                           status_ids = Status.objects(),
                           statuses = statuses,
                           authorized=logged_in())

@app.route("/update", methods=['POST'])
@require_login
def update():
    r = request.get_json()
    k = r['kernel_id'];
    c = r['cve_id'];
    s = r['status_id'];

    Patches.objects(kernel=k, cve=c).update(status=Status.objects.get(short_id=s).id)
    progress = utils.getProgress(k)
    Kernel.objects(id=k).update(progress=progress)
    return jsonify({'error': 'success', 'progress': progress})


@app.route("/addcve", methods=['POST'])
@require_login
def addcve():
    errstatus = "Generic error"
    cve_id = None
    r = request.get_json()
    cve = r['cve_id']
    notes = r['cve_notes']
    if not notes:
        notes = ""
    if cve and len(notes) >= 10:
        splitted = cve.split('-')
        if CVE.objects(cve_name=cve):
            errstatus = cve + " already exists!"
        elif (len(splitted) != 3 or len(splitted[1]) != 4 or
                (splitted[0] != "CVE" and splitted[0] != "LVT")):
            errstatus = "'" + cve + "' is invalid!"
        else:
            CVE(cve_name=cve, notes=notes).save()
            cve_id = CVE.objects.get(cve_name=cve)['id']
            for k in Kernel.objects():
                Patches(cve=cve_id, kernel=k.id, status=Status.objects.get(short_id=1)['id']).save()
                k.progress = utils.getProgress(k.id)
                k.save()
            if splitted[0] != "LVT":
                mitrelink = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name='
                Links(cve_id=cve_id, link=mitrelink+cve).save()
            errstatus = "success"
    else:
        if not cve:
            errstatus = "No CVE specified!"
        elif len(notes) < 10:
            errstatus = "Notes have to be at least 10 characters!";

    return jsonify({'error': errstatus, 'cve_id': str(cve_id)})

@app.route("/addkernel", methods=['POST'])
@require_login
def addkernel():
    errstatus = "Generic error"
    r = request.get_json()
    kernel = r['kernel']

    if kernel:
        if Kernel.objects(repo_name=kernel):
            errstatus = "'" + kernel + "' already exists!"
        else:
            v, n = utils.getVendorNameFromRepo(kernel)
            if v is "error" or n is "error":
                errstatus = "'" + kernel + "' is invalid!"
            else:
                utils.addKernel(kernel)
                errstatus = "success"
    else:
        errstatus = "No kernel name specified!"

    return jsonify({'error': errstatus})


@app.route("/editcve/<string:cvename>")
@require_login
def editcve(cvename = None):
    if cvename and CVE.objects(cve_name=cvename):
        cve = CVE.objects.get(cve_name=cvename)
        return render_template('editcve.html',
                               cve=cve,
                               links=Links.objects(cve_id=cve['id']))
    else:
        msg = cvename + " is invalid or doesn't exist!"
        return render_template('editcve.html', msg=msg)

@app.route("/deletecve/<string:cvename>")
@require_login
def deletecve(cvename = None):
    if cvename and CVE.objects(cve_name=cvename):
        utils.nukeCVE(cvename)
        return render_template('deletedcve.html', cve_name=cvename)
    return error()

@app.route("/addlink", methods=['POST'])
@require_login
def addlink():
    errstatus = "Generic error"
    link_id = ""
    r = request.get_json()
    c = r['cve_id']
    l = r['link_url']
    d = r['link_desc']

    if not CVE.objects(id=c):
        errstatus = "CVE doesn't exist"
    elif Links.objects(cve_id=c, link=l):
        errstatus = "Link already exists!"
    else:
        Links(cve_id=c, link=l, desc=d).save()
        link_id = Links.objects.get(cve_id=c, link=l)['id']
        errstatus = "success"

    return jsonify({'error': errstatus, 'link_id': str(link_id)})

@app.route("/deletelink", methods=['POST'])
@require_login
def deletelink():
    errstatus = "Generic error"
    r = request.get_json()
    l = r['link_id']

    if l and Links.objects(id=l):
        Links.objects(id=l).delete()
        errstatus = "success"
    else:
        errstatus = "Link doesn't exist"

    return jsonify({'error': errstatus})

@app.route("/editnotes", methods=['POST'])
@require_login
def editnotes():
    errstatus = "Generic error"
    r = request.get_json()
    c = r['cve_id']
    n = r['cve_notes']

    if c and CVE.objects(id=c):
        CVE.objects(id=c).update(set__notes=r['cve_notes'])
        errstatus = "success"
    elif not n or len(n) < 10:
        errstatus = "Notes have to be at least 10 characters!";
    else:
        errstatus = "CVE doesn't exist"

    return jsonify({'error': errstatus})

@app.route("/editlink", methods=['POST'])
@require_login
def editlink():
    errstatus = "Generic error"
    r = request.get_json()
    l = r['link_id']

    if l and Links.objects(id=l):
        Links.objects(id=l).update(set__link=r['link_url'], set__desc=r['link_desc'])
        errstatus = "success"
    else:
        errstatus = "Link doesn't exist"

    return jsonify({'error': errstatus})

@app.route("/getlinks", methods=['POST'])
def getlinks():
    r = request.get_json()
    c = r['cve_id'];
    return Links.objects(cve_id=c).to_json()

@app.route("/api/cves")
def get_cves():
    obj = {}
    for el in CVE.objects():
        obj[el.cve_name] = {'notes': el.notes, 'links': []}
        links = Links.objects(cve_id=el.id)
        for link in links:
            obj[el.cve_name]['links'].append({'link': link.link, 'desc': link.desc})
    return jsonify(obj)

@app.route("/getnotes", methods=['POST'])
def getnotes():
    r = request.get_json()
    c = r['cve_id']
    return CVE.objects(id=c).to_json()

@app.route("/check/<string:k>/<string:c>")
def check(k, c):
    statusid = Patches.objects.get(kernel=Kernel.objects.get(repo_name=k).id,
                                   cve=CVE.objects.get(cve_name=c).id).status
    status = Status.objects.get(id=statusid).text
    return jsonify({'kernel': k, 'cve': c, 'status': status})

@app.route("/deprecate", methods=['POST'])
@require_login
def deprecate():
    r = request.get_json()
    k = r['kernel_id']
    d = r['deprecate']
    if d == 'True':
      new_state = False
    else:
      new_state = True
    Kernel.objects(id=k).update(deprecated=new_state)

    return jsonify({'error': "success"})

###
# cache helper functions
###

