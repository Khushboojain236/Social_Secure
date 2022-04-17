
from webbrowser import get
from pymongo import MongoClient
from getpass import getpass
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import pymongo
from cryptography.fernet import Fernet
import certifi
import base64



ca = certifi.where()
client = pymongo.MongoClient("mongodb+srv://khushboo236:236Khushboo@cluster0.fbyph.mongodb.net/test",tlsCAFile=ca )
db = client.get_database('networks2')
users = db.users
groups = db.groups


def main():
    try:
        userlogin = None
        while True:
            value = input('\nEnter help for options or enter what you want to do?  ')
            value = value.split(' ')
            if value[0] == 'help':
             print_help()
             continue

            if userlogin is None:
                if value[0] == 'register':
                    register()
                elif value[0] == 'login':
                    userlogin=log_in(userlogin)
                else:
                    print("Please enter help :) ")
            else:
                if value[0] == 'create':
                    # enter create and group
                    group_create(userlogin,value[1])
                if value[0] == 'logout':
                    # enter logout 
                    userlogin=log_out(userlogin)
                if value[0] == 'post':
                    # enter post and group
                    group_post(userlogin,value[1])
                if value[0] == 'view':
                    # enter view and group name
                    group_view(userlogin,value[1])
                if value[0] == 'invite':
                    # can only invite existimg members
                    # invite "MemberName" "GroupName"
                    invite_member(userlogin,value[1],value[2])
                if value[0] == 'join':
                    # add me to GroupName
                    join_group(userlogin,value[1])
                if value[0] == 'inbox':
                   userlogin=view_inbox(userlogin)
                if value[0] == 'remove':
                    # MemberName from GroupName
                    remove_member(userlogin,value[1],value[2])
                if value[0] == 'clear':
                    inbox_clear(userlogin)
                    
                
    except (KeyboardInterrupt, SystemExit):
        print('\nExit')    


def print_help():
	print("""""
    When not logged in:
        login
        register
        help
    When logged in or after registering:
        logOut
        create (GroupName)
        post (GroupName)
        view (GroupName)
        invite (MemberName,GroupName)
        join(GroupName)
        inbox
        clear
        """"")
 
 
    

def register():
    print('Please enter a username and password.')
    username = input('Username: ')
    password = getpass()
    private_key,public_key=key_generation()
    new_user = {
        'username' : username,
        'password' : password,
        'private_key': private_key.exportKey(),
        'public_key':public_key.exportKey(),
        'group_keys':{},
        'invites':{}
    }
    users.insert_one(new_user)
    print('User registered : {0}'.format(username))

def key_generation():
    private_key = RSA.generate(2048)
    public_key= private_key.publickey()
    return private_key,public_key

def encrypt_group_key(user, group_key):
    public_key = user['public_key']
    public_key = RSA.importKey(public_key)
    cipher = PKCS1_OAEP.new(key = public_key)
    encrypted_key = cipher.encrypt(group_key)
    return encrypted_key

def decrypt_group_key(user, group_name):
    encrypted_key = user['group_keys'][group_name]
    private_key = user['private_key']
    private_key = RSA.importKey(private_key)
    decrypt = PKCS1_OAEP.new(key = private_key)
    group_key = decrypt.decrypt(encrypted_key)
    return group_key

def log_in(userlogin):
    username = input('Username: ')
    user = users.find_one({'username': username})
    if user:
        password = getpass()
        if password == user['password']:
            userlogin = user
            print('Logged in as: {0}'.format(userlogin['username']))
        else:
            print('Wrong password.')
    else:
        print('User not found.')
    return userlogin

def log_out(user):
    user = None
    print('Logged out.')
    return user

def group_post(user,group_name):
    group = groups.find_one({'group_name': group_name})
    if group:
        if membership_check(user, group):
            message = input('Post to {0}: \n'.format(group_name))
            group_key = decrypt_group_key(user, group_name)
            
            # encrypt the message using the group_key
            fer = Fernet(group_key)
            token = fer.encrypt(message.encode())
            messages = group['messages']
            messages.append((user['username'],token))
            group_update = {
                'messages': messages
            }
            groups.update_one({'group_name': group_name}, {'$set': group_update}) 
        else:
            print('To post you need to be part of group')
    else:
        print('No group with this name.')
        
def membership_check(user, group):
    if user['username'] in group['users']:
        return True
    return False

def group_create(admin,group_name):
    admin_name= admin['username']
    group_key=Fernet.generate_key()
    fer = Fernet(group_key)
    message = 'Created {0}. Hello :) '.format(group_name)
    token = fer.encrypt(message.encode())
    new_group = {
        'admin':admin_name,
        'group_name': group_name,
        'users': [admin_name],
        'messages': [(admin_name,token)]
    }
    groups.insert_one(new_group)
    print('Created group: {0}'.format(group_name))
    
    encrypted_key = encrypt_group_key(admin, group_key)
    group_keys = admin['group_keys']
    group_keys.update({group_name: encrypted_key})
    admin_updates = {
        'group_keys': group_keys
    }
    users.update_one({'username': admin_name}, {'$set': admin_updates}) 
    

def group_view(user,group_name):
    group = groups.find_one({'group_name': group_name})
    messages = group['messages']
    
    if user['username'] not in group['users']:
        print('\ nWelcome to {0}'.format(group_name))
        for x in messages:
            print(x[1].decode() + '\n') 
    
    else:
        group_key = decrypt_group_key(user,group_name)
        fer = Fernet(group_key)
        messages = group['messages']
        print('\n Welcome to {0}'.format(group_name))
        for x in messages:
            print((fer.decrypt(x[1])).decode() + '\n') 
            
def invite_member(user,mem_name,group_name):
    group = groups.find_one({'group_name': group_name})
    if group:
        if (membership_check(user,group)):
            group_key = decrypt_group_key(user, group_name)
            new_mem= users.find_one({'username': mem_name})
            if new_mem:
                if new_mem['username']==user['username']:
                    print('Cannot invite yourself')
                
                else:
                    invite_key = encrypt_group_key(new_mem, group_key)
                    invites = new_mem['invites']
                    invites.update({group_name: invite_key})
                    new_mem_upadates = {
                        'invites': invites
                    }
                    users.update_one({'username': new_mem['username']}, {'$set': new_mem_upadates}) 
                    print('Invite to \'{0}\' has been sent to \'{1}\''.format(group_name, new_mem['username']))
            
            else:
                print('User does not exist')
        else:
            print('You need to be a member to invite')
    else:
        print('No group with that name')

def join_group(user,group_name):
    group = groups.find_one({'group_name': group_name})
    if group:
        user = users.find_one({'username': user['username']})
        try:
            invite_key = user['invites'][group_name]
            invites = user['invites']
            try:
                del invites[group_name]
            except KeyError:
                print('Unable to delete the invite.')
            
            user_groups = user['group_keys']
            user_groups.update({group_name: invite_key})
            user_update = {
                'group_keys': user_groups,
                'invites': invites
            }
            users.update_one({'username': user['username']}, {'$set': user_update}) 

            # decrypt invite_key into group_key to encrypt join message
            group_key = decrypt_group_key(user, group_name)
            fer = Fernet(group_key)
            
            message = '\'{0}\' has joined the group. Welcome!'.format(user['username'])
            token = fer.encrypt(message.encode())
            messages = group['messages']
            messages.append((user['username'], token))


            group_users = group['users']
            group_users.append(user['username'])
            group_updates = {
                'users': group_users,
                'messages': messages
            }
            groups.update_one({'group_name': group_name}, {'$set': group_updates})
            print('You have successfully joined {0}'.format(group_name)) 
        except KeyError:
            print('You do not hold an invitation to this group.')
            return user
    else:
        print('This group does not exist.')
    return user

def view_inbox(user):
    viewing_user = users.find_one({'username': user['username']})
    if viewing_user['invites']:
        print('Invitation to {0} group(s).'.format(len(viewing_user['invites'])))
        for x in viewing_user['invites']:
            print('{0}'.format(x))
    else:
        print('Inbox is empty.')
    return viewing_user

def remove_member(user,mem_name,group_name):
    group = groups.find_one({'group_name': group_name})
    if group:
        if user['username'] == group['admin']:
            if user['username'] == user:
                print('You are the admin.')
            else:
                member = users.find_one({'username': mem_name})
                if member:
                    if membership_check(member, group):
                        user_groups = member['group_keys']
                        try:
                            del user_groups[group_name]
                        except KeyError:
                            pass
                        user_update = {
                            'group_keys': user_groups
                        }
                        users.update_one({'username': member['username']}, {'$set': user_update}) 
                        print('\'{0}\' has been kicked from \'{1}\'.'.format(member['username'], group_name))
                        
                       
                        group_key = decrypt_group_key(user, group_name)
                        fer = Fernet(group_key)
                        message = '\'{0}\' has been kicked from \'{1}\'.'.format(member['username'], group_name)
                        token = fer.encrypt(message.encode())
                        messages = group['messages']
                        messages.append((user['username'],token))
                        
                        group_users = group['users']
                        group_users.remove(mem_name)
                        group_updates = {
                            'users': group_users,
                            'messages': messages
                        }
                        groups.update_one({'group_name': group_name}, {'$set': group_updates})
                    else:
                        print('User is not part of this group.')
                else:
                    print('User does not exist.')
        else:
            print('Only admin can remove people')
    else:
        print('No group with that name')


def inbox_clear(user):
    invites = {}
    invites_update = {
        'invites': invites
    }
    users.update_one({'username': user['username']}, {'$set': invites_update}) 
    print('Inbox has been cleared')

        
if __name__ == '__main__':
    main()
