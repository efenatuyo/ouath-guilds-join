from flask import Flask, request
import requests
import datetime
import configparser
import threading
import asyncio
import discord
from discord.ext import commands
bot = commands.Bot(command_prefix="$", intents=discord.Intents.all())



config = configparser.ConfigParser(allow_no_value=True)
config.read('database.ini')

owners = config['config']['owners'].split(', ')

class Restore:
    class DotDict(dict):
        def __getattr__(self, attr):
           return self[attr]
    
    def __init__(self, bot_token, client_id, client_secret, redirect_uri, guild_id, verify_role_id):
        self.bot_token = bot_token
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.guild_id = guild_id
        self.verify_role_id = verify_role_id
        self.app = Flask(__name__)
        self.app.route('/auth/discord/callback')(self.discord_callback)
        flask_thread = threading.Thread(target=self.run)
        flask_thread.start()
        self.extra_events = {}

    def call_event(self, name, *args, **kwargs):
        name(self, **kwargs)
        
    def run(self):
        self.app.run(threaded=True, debug=False)

    def discord_callback(self):
        code = request.args.get('code')
        
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.redirect_uri,
            'scope': "identify guilds.join",
        }
        
        headers = {
            "Authorization": f"Bot {self.bot_token}",
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        response = requests.post('https://discord.com/api/oauth2/token', data=data, headers=headers)
        if response.status_code == 200:
           auth_data = response.json()
           access_token = auth_data['access_token']
           refresh_token = auth_data['refresh_token']
        
        

           user = self.get_discord_id(access_token)
           if user.success:
        
              info = {
                      'access_token': access_token,
                      'refresh_token': refresh_token,
                      'user_id': user.id,
                      'expires_in': str(datetime.timedelta(seconds=int(auth_data['expires_in'])) + datetime.datetime.now()),
                      'key': config['config']['private_key']
                      }
              

              self.write_to_database(info)
              self.call_event(on_verify, info=info)
              return Restore.DotDict({'text': "Succesfully verifed. You can return to the server", 'success': True, 'status_code': 200})
           else:
               return Restore.DotDict({'text': response.json(), 'success': False, 'status_code': response.status_code})
        else:
            return Restore.DotDict({'text': response.json(), 'success': False, 'status_code': response.status_code})
    
    def add_user_to_guild(self, user_id, guild_id):
     check = self.check_access_token(config[str(user_id)]['access_token'])
     if check.success:
        
        headers = {
                   "Authorization": f"Bot {self.bot_token}",
                   "Content-Type": "application/json"
        }
        data = {
                "access_token": config[user_id]['access_token']
        }
        response = requests.put(f"https://discord.com/api/v9/guilds/{guild_id}/members/{user_id}", headers=headers, json=data)
        if response.status_code == 201:
            return Restore.DotDict({'text': 'Succesfully added user to guild', 'success': True, 'status_code': 200})
        
        elif response.status_code == 204:
            return Restore.DotDict({'text': 'User already in guild', 'success': True, 'status_code': 204})
        else:
            return Restore.DotDict({'text': response.json(), 'success': False, 'status_code': response.status_code})
     else:
        return Restore.DotDict({'text': check.text, 'success': check.success, 'status_code': check.status_code})
    
    def write_to_database(self, info):
        if info['key'] != config['config']['private_key']:
            return Restore.DotDict({'text': "invalid key", 'status_code': 400})
        config['users'][info['user_id']] = None
        config[info['user_id']] = {}
        config[info['user_id']]['access_token'] = info['access_token']
        config[info['user_id']]['refresh_token'] = info['refresh_token']
        config[info['user_id']]['expires_in'] = info['expires_in']
        with open('database.ini', 'w') as configfile:
            config.write(configfile)
        
        return Restore.DotDict({'text': 'Succesfully written to database', 'success': True, 'status_code': 200})
    
    def refresh_token(self, refresh_token):
        data = {
               'client_id': self.client_id,
               'client_secret': self.client_secret,
               'grant_type': 'refresh_token',
               'refresh_token': refresh_token
        }

        headers = {
                  'Content-Type': 'application/x-www-form-urlencoded'
        }

        response_auth = requests.post('https://discord.com/api/v9/oauth2/token', data=data, headers=headers)
        if response_auth.status_code == 200:
            auth_data = response_auth.json()
            access_token = auth_data['access_token']
            refresh_token = auth_data['refresh_token']
            response_user = self.get_discord_id(access_token)
            if response_user.success:
                        info = {
                                'access_token': access_token,
                                'refresh_token': refresh_token,
                                'user_id': response_user.id,
                                'expires_in': str(datetime.timedelta(seconds=int(auth_data['expires_in'])) + datetime.datetime.now()),
                                'key': config['config']['private_key']
                               }
                        self.write_to_database(info)
                        return Restore.DotDict({'text': "Succefully updated access token", 'success': True, 'status_code': 200})
            else:
               return Restore.DotDict({'text': response_user.text, 'success': False, 'status_code': response_user.status_code})
        else:
            return Restore.DotDict({'text': response_auth.json(), 'success': False, 'status_code': response_auth.status_code})
    
    def get_discord_id(self, access_token):
          
           headers = {
            'Authorization': f'Bearer {access_token}'
           }
           response = requests.get('https://discordapp.com/api/users/@me', headers=headers)
           if response.status_code == 200:
               user_data = response.json()
               user_id = user_data['id']
               return Restore.DotDict({'text': "successfully scraped user_id", 'id': user_id, 'success': True, 'status_code': 200})
           else:
               return Restore.DotDict({'text': response.json(), 'success': False, 'status_code': response.status_code})
               
    def check_access_token(self, access_token):
        user = self.get_discord_id(access_token)
        if user.success:
            
         if datetime.datetime.strptime(config[str(user.id)]['expires_in'], '%Y-%m-%d %H:%M:%S.%f') > datetime.datetime.now():
            return Restore.DotDict({'text': "access token still valid", 'success': True, 'status_code': 200})
         else:
            refresh_token = config[user.id]['refresh_token']
            if self.refresh_token(refresh_token).success:
               
               return Restore.DotDict({'text': "access token expired but updated successfully", 'success': True, 'status_code': 200})
            else:
               return Restore.DotDict({'text': "access token expired and couldn't be updated", 'success': False, 'status_code': 400})
        else:
            return Restore.DotDict({'text': "invalid access token", 'success': False, 'status_code': 401})
    

def on_verify(self, info):
    guild_id = self.guild_id
    user_id = info['user_id']
    headers = {'Authorization': f'Bot {self.bot_token}'}
    url = f'https://discord.com/api/v9/guilds/{guild_id}/members/{user_id}/roles/{self.verify_role_id}'
    response = requests.put(url, headers=headers)
    response.raise_for_status()


restore = Restore(bot_token=config['config']['bot_token'], client_id=config['config']['client_id'], client_secret=config['config']['client_secret'], redirect_uri=config['config']['redirect_uri'], guild_id=config['config']['guild_id'], verify_role_id=config['config']['verify_role_id'])

@bot.command(name="restore")
async def command_restore(ctx, guild_id):
    if not ctx.author.id in owners:
        return await ctx.reply("You are not allowed to restore")
    
    for user_id in config['users']:
        restore.add_user_to_guild(user_id, guild_id)
    
bot.run(config['config']['bot_token'])
