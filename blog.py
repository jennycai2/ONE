import logging
import os
import re
import urllib2
import urllib

import random
import hashlib
import hmac

from string import letters

import webapp2
import jinja2

from xml.dom import minidom
from google.appengine.ext import db
from webapp2_extras import json
from google.appengine.api import memcache
from datetime import datetime, timedelta

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env=jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                             autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw)) 

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

def age_set(key, val):
    save_time = datetime.utcnow()
    memcache.set(key, (val, save_time))

def age_get(key):
    r = memcache.get(key)
    if r:
        val, save_time = r
        age = (datetime.utcnow() - save_time).total_seconds()
    else:
        val, age = None, 0
    return val, age
        
def add_post(ip, post):
    post.put()
    get_posts(update = True)
    return str(post.key().id)

def get_posts(update = False):
    q = Post.all().order('-created').fetch(limit=10)
    mc_key = 'BLOGS'

    posts, age = age_get(mc_key)
    if update or posts is None:
        posts = list(q)
        age_set(mc_key, posts)

    return posts, age

def age_str(age):
    s = 'Queried %s seconds ago'
    age = int(age)
    if age == 1:
        s = s.replace('seconds', 'second')
    return s % age

class Flush(Handler):
    def get(self):
        memcache.flush_all()
        #posts, age = get_posts(True)
        self.redirect('/')



class PostPage(Handler):
    def get(self, post_id):
        post_key = 'POST_' + post_id
        post, age = age_get(post_key)
        if not post:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            age_set(post_key, post)
            age = 0

        if not post:
           self.error(404)
           return           

        self.render("permalink.html", post = post, age = age_str(age))


class NewPost(Handler):
    def get(self):
    	logging.info("THIS IS A GET")
    	self.render('newpost.html')
      
    def post(self):
    	logging.info("THIS IS A POST")
        subject=self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content)
            p.put()
            self.redirect('/%s' % str(p.key().id()))
            logging.info("WRITE TO DATABASE for %s", subject)
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)


SECRET = "Xxhkg992k,m,788GJIEKL"
def hash_str(s):
        return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
        return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
        h=str(h)
        val = h.split('|')[0]
        if h == make_secure_val(val):
                return val

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt=make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, pw, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, pw, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class ButtonPress(db.Model):
    person_id = db.StringProperty(required = True)
    skype = db.StringProperty()
    hashtag = db.StringProperty()
    pressed = db.DateTimeProperty(auto_now_add = True)
    pair_with = db.StringProperty()
      
class User(db.Model):
    #name = db.StringProperty(required = True)
    email = db.StringProperty()
    pw_hash = db.StringProperty(required = True) 
    skype = db.StringProperty()
    hashtag = db.StringProperty()
    joined = db.DateTimeProperty(auto_now_add = True)

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, email):
        u = User.all().filter('email =', email).get()
        return u

    @classmethod
    def register(cls, email, pw, skype, hashtag):
        pw_hash = make_pw_hash(email, pw)
        return User(parent = users_key(), email = email, pw_hash = pw_hash, skype = skype, hashtag=hashtag)

    @classmethod
    def login(cls, email, pw):
        u = cls.by_name(email)
        if u and valid_pw(email, pw, u.pw_hash):
            return u
  
        
class BaseHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t=jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
     
    def set_secure_cookie(self, name, val):

        cookie_val = str(make_secure_val(val))
        #cookie_val = str((val))
        
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name) 
        return cookie_val and check_secure_val(cookie_val) 
        
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')

        self.user = uid and User.by_id(int(uid))
 
    def get_post_json(self, post):
        return json.encode({"subject":post.subject, "content": post.content})       

class PostJson(BaseHandler):
    def get(self, post_id):
        self.response.content_type = 'application/json; charset=utf-8'
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return
        self.write(self.get_post_json(post))


class BlogJson(BaseHandler):
    def get(self):
        self.response.content_type = 'application/json; charset=utf-8'
        posts = Post.all().order('-created')
        json = '['
        for post in posts:
            json += self.get_post_json(post) + ','
        if json[-1] == ',':
            self.write(json[:-1] + ']')


PASSWORD_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASSWORD_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
    return email and EMAIL_RE.match(email)

SKYPE_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_skype(skype):
    #return skype and SKYPE_RE.match(skype)
    return skype

def valid_hashtag(hashtag):
    return (hashtag == 'startup' or hashtag == 'speech' or hashtag == 'language')

class Signup(BaseHandler):
    def get(self):
        self.render("signup-form.html")        
        
    def post(self):
        self.password=self.request.get('password')
        self.email=self.request.get('email')
        self.skype=self.request.get('skype')
        #self.hashtag=self.request.get('hashtag')
        self.hashtag = 'speech'

        logging.info("skype is %s", self.skype)

        have_error=False

        params=dict(email=self.email)

        if not valid_password(self.password):
            params['error_password'] = "That's not a valid password."
            have_error=True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error=True

        if not valid_skype(self.skype):
            params['error_skype'] = "That's not a valid skype."
            have_error=True

        #if not valid_hashtag(self.hashtag):
        #    params['error_hashtag'] = "supported hashtag is startup, speech, or language."
        #    have_error=True

        if (have_error):
            self.render("signup-form.html", **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError          

class Test(BaseHandler):
    def get(self):

        AVAIL_TIME = 30
        MIN_TALK_TIME = 5
        TIME = (AVAIL_TIME - MIN_TALK_TIME) #normally set this to 25 minutes
        #username=self.user.email
        debug = False
        #debug = True
        if debug:
         
            #DEBUG USERS
            users = debug_users()
            self.response.write('USERS ________________________ email hashtag skype <br>') 

            for b in users:
            
                self.response.write('<br>%s,' %b.email) 
                
                self.response.write(' %s' %b.skype)
                b.delete()

            #DEBUG BUTTON PRESS
            buttons = debug_buttons()
            self.response.write(' <br><br>BUTTON PRESS___________________________Who When Hashtag Skype Pair-with <br>') 

            for b in buttons:
            
                time_delta = datetime.now().replace(microsecond=0) - b.pressed.replace(microsecond=0)
                minutes = int(time_delta.total_seconds())
                minutes = minutes / 60
                self.response.write('<br>%s,' %b.person_id) 
                #self.response.write(' %s,' %b.hashtag) 
                self.response.write(' %s ago,' %time_delta) 
                self.response.write(' pair is %s,' %b.pair_with)
                self.response.write(' time limit %s ' %(minutes < TIME))
                b.delete()

class Stats(BaseHandler):
    def get(self):

        AVAIL_TIME = 30
        MIN_TALK_TIME = 5
        TIME = (AVAIL_TIME - MIN_TALK_TIME) #normally set this to 25 minutes
        #username=self.user.email
        debug = False
        debug = True
        if debug:
           
            #DISPLAY for the past 24 hours, how many users at each half hour 
            #does DB provide a count?
            buttons = debug_buttons()
            self.response.write(' <br><br>BUTTON PRESS<br>') 

            for b in buttons:
            
                time_delta = datetime.now().replace(microsecond=0) - b.pressed.replace(microsecond=0)
                minutes = int(time_delta.total_seconds())
                minutes = minutes / 60
                #self.response.write('<br>%s,' %b.person_id) 
                #self.response.write(' %s,' %b.hashtag) 
                self.response.write('<br>%s ago,' %time_delta) 
                if (b.pair_with):
                    self.response.write(' initiated the call')
                else:
                    self.response.write(' waited')
                #self.response.write(' time limit %s ' %(minutes < TIME))
                               
  
class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.email)
        if u:
            msg = 'That email already registered.'
            self.render('signup-form.html', error_email = msg)
        else:
            u = User.register(self.email, self.password, self.skype, 'speech')
            u.put()

            self.login(u)
            self.redirect('/practice')


class Login(BaseHandler):
    def get(self):
        self.render("signin-form.html")        
        
    def post(self):
        email=self.request.get('email')
        password=self.request.get('password')
            
        logging.info("email is %s" % email)
        
        u = User.login(email, password)
        if (u):
            self.login(u)
            self.redirect('/practice')
        else:
            msg = 'Invalid sign in'
            self.render("signin-form.html", error = msg)   

class Logout(BaseHandler):       
     def get(self):
        self.logout()
        self.redirect('/')           

def debug_users():
    key = 'recent'
    #buttons = memcache.get(key)
    update = True
    if update:
        #read from DB
        #if the other user doesn't respond, the current user can press the button again
        #read the most entry in the database
        logging.info("READ FROM DB")
        users = db.GqlQuery("SELECT * FROM User ORDER BY joined DESC LIMIT 10")
    
    return users

def debug_buttons():
    key = 'recent'
    #buttons = memcache.get(key)
    update = True
    if update:
        #read from DB
        #if the other user doesn't respond, the current user can press the button again
        #read the most entry in the database
        logging.info("READ FROM DB")
        buttons = db.GqlQuery("SELECT * FROM ButtonPress ORDER BY pressed DESC LIMIT 10")
        logging.info("read from DB, button is %s" % buttons)
        for b in buttons:
            logging.info("\nENTRY user %s" % b.person_id)
            
            logging.info("hour %s" % b.pressed.hour)
            logging.info("minute %s" % b.pressed.minute)
            logging.info("minute %s" % b.skype)
            logging.info("minute %s" % b.pair_with)
            
        #buttons = list(buttons)
        #memcache.set(key, buttons)
        #logging.info("after caling list, button is %s" % buttons)
    return buttons

def readButtonPressFromDB(hashtag):
    #currently only handle one hashtag - 'speech'
    buttons = db.GqlQuery("SELECT * FROM ButtonPress WHERE hashtag = 'speech' ORDER BY pressed DESC LIMIT 1")
    if buttons:
        for button in buttons:
            previous_user = button.person_id

            # Get current time and compute the time difference
            time_delta = datetime.now().replace(microsecond=0) - button.pressed.replace(microsecond=0)
            minutes = int(time_delta.total_seconds())
            minutes = minutes / 60
            logging.info("minutes %s" % minutes)
            return button.person_id, button.skype, button.pair_with, minutes
    else:        
        # we never come to this path, even though there is no previous button press, buttons is not None but button is None
        logging.info("VERY FIRST BUTTON PRESS")
    return None, None, None, 0

def writeButtonPressToDB(user, skype, hashtag, pair_with):
    bp = ButtonPress(person_id = user, skype = skype, hashtag = hashtag, pair_with = pair_with)
    bp.put()      
    return True

def ButtonPressAPI(user, skype, hashtag):
    AVAIL_TIME = 30
    MIN_TALK_TIME = 5
    
    # Read Previous ButtonPress 
    previous_user, previous_skype, pair_with, minutes = readButtonPressFromDB(hashtag)

    minutes = AVAIL_TIME - minutes # if one presses button 5 minutes, he can talk for 25 minutes
    
    if (pair_with == None and (minutes > MIN_TALK_TIME)):
        # This includes the first button press
        pair_with = previous_user  
        pair_with_skype = previous_skype
    else:
        pair_with = None 
        pair_with_skype = None           

    writeButtonPressToDB(user, skype, hashtag, pair_with)             
    return pair_with, pair_with_skype, minutes



def recent_button(hashtag, update = False):
    button = None
    #key = 'recent'
    #button = memcache.get(key)
    if button is None or update:
        #read from DB
        #if the other user doesn't respond, the current user can press the button again
        #read the most entry in the database
        hashtag = 'speech'
        if hashtag == 'startup':
            buttons = db.GqlQuery("SELECT * FROM ButtonPress WHERE hashtag = 'startup' ORDER BY pressed DESC LIMIT 1")
        elif hashtag == 'speech':
            buttons = db.GqlQuery("SELECT * FROM ButtonPress WHERE hashtag = 'speech' ORDER BY pressed DESC LIMIT 1")
        else:
            buttons = db.GqlQuery("SELECT * FROM ButtonPress WHERE hashtag = 'language' ORDER BY pressed DESC LIMIT 1")
     
        logging.info("READ FROM DB, buttons %s" % buttons)
        

        if (buttons):
            for button in buttons:
                #memcache.set(key, button)

                logging.info("READ FROM DB, button is %s" % button)
                logging.info("READ FROM DB, person_id is %s" % button.person_id)
                return button
            #logging.info("hour %s" % b.pressed.hour)
            #logging.info("minute %s" % b.pressed.minute)

        #buttons = list(buttons)
        
        #logging.info("after caling list, button is %s" % buttons)
    return button
                            
class PracticeFront(Handler):
    def get(self):
        #if self.user:
        #    time = datetime.now().replace(microsecond=0).time()
        #    self.render('practice.html', username=self.user.email, time = time)
        #else:
        self.render('mainpage.html')
    def post(self):
        self.redirect('/signup')

class PracticeJson(BaseHandler):
    # don't define get and a user will get "405 Method Not Allowed"
    def post(self):
        if self.user:
            pair_with, pair_with_skype, minutes = ButtonPressAPI(self.user.email, self.user.skype, self.user.hashtag) 
            self.response.content_type = 'application/json; charset=utf-8'         
            self.write('[')
            self.write(json.encode({"pair_with":pair_with, "pair_with_skype": pair_with_skype, "minutes": minutes}))      
            self.write(']') 
        else:
            self.error(404) 

class Starter(BaseHandler):
    def get(self):
        self.render('index.html')
    

class Practice(BaseHandler):
    def get(self):
        if self.user:
            time = datetime.now().replace(microsecond=0).time()
            self.render('practice.html', username=self.user.email, time = time)
        else:
            self.redirect('/signup')

    def post(self):             
        if self.user:
           pair_with, pair_with_skype, minutes = ButtonPressAPI(self.user.email, self.user.skype, self.user.hashtag)      
           if pair_with:
                msg = 'Congratulations! %s' %pair_with
                msg += ' can speak/coach for %s minutes. ' %minutes     
                connected = True                
           else:
                msg = 'Thanks! The next user will call you through Skype.'
                connected = False
                
           time = datetime.now().replace(microsecond=0).time()
           self.render('practice.html', username=self.user.email, time = time, msg=msg, skype=pair_with_skype, connected=connected)  
        else:
            self.redirect('/signup')     

application = webapp2.WSGIApplication([
	('/?', PracticeFront),
    
    ('/test', Test),
    ('/stats', Stats),
    ('/signup', Register),
    ('/signin', Login),
    ('/signout', Logout),
    ('/practice.json', PracticeJson),
    ('/practice', Practice)], 
    debug=True)