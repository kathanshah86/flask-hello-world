from flask import Flask, request, render_template, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import Integer, String, Boolean
import random
import string
import hashlib
import hmac
from datetime import datetime
from flask_uploads import UploadSet , IMAGES , configure_uploads
from datetime import timedelta
import os
from dotenv import load_dotenv
import razorpay
import json

app = Flask(__name__, template_folder='template')



def password_hash(password: str) -> str:
    return hmac.new(os.getenv('SECRET_KEY').encode(), str(password).encode(), digestmod=hashlib.sha512).hexdigest()

load_dotenv()

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///battlemitra.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
database = SQLAlchemy()
database.init_app(app)
paymentClient = razorpay.Client(auth=(os.getenv('RZP_API'), os.getenv('RZP_SECRET')))

adminClinet = os.getenv('ADMIN_CLIENT')
adminPassword = password_hash(os.getenv('ADMIN_PASSWORD'))


pictures = UploadSet('photos',IMAGES)

UPLOAD_FOLDER = "static/user_upload"
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}



app.permanent_session_lifetime = timedelta(days=14)

def igen(length: int) -> str:
    """
    Generates random codes of specified length.

    Args:
        length (int): Length of the generated code.

    Returns:
        str: Generated code.
    """
    letters_and_digits = string.ascii_letters + string.digits
    genid = ''.join((random.choice(letters_and_digits) for i in range(length)))
    return genid


class users(database.Model):
    """
    Represents the users table in the database.
    """
    num: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String)
    email: Mapped[str] = mapped_column(String)
    password: Mapped[str] = mapped_column(String)
    userid: Mapped[str] = mapped_column(String,default=igen(8))
    dp: Mapped[str] = mapped_column(String, default="original.jpg")
    tournamentsPlayed: Mapped[int] = mapped_column(Integer, default=0)
    tournamentsWon: Mapped[int] = mapped_column(Integer, default=0)
    bestRank: Mapped[int] = mapped_column(Integer, default=0)
    totalEarnings: Mapped[int] = mapped_column(Integer, default=0)
    tags: Mapped[str] = mapped_column(String, default="None")
    bio: Mapped[str] = mapped_column(String, default="None")
    gamerExperience: Mapped[str] = mapped_column(String, default="None")
    createdAt: Mapped[str] = mapped_column(String, default=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    

class tournamentInfo(database.Model):
    """
    Represents the users table in the database.
    """
    num: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host: Mapped[str] = mapped_column(String)
    title: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String)
    gameType: Mapped[str] = mapped_column(String)
    startDate: Mapped[str] = mapped_column(String)
    endDate: Mapped[str] = mapped_column(String)
    gameFormat: Mapped[str] = mapped_column(String)
    prizePool: Mapped[str] = mapped_column(String)
    participantsCount: Mapped[int] = mapped_column(Integer)
    maxParticipants: Mapped[int] = mapped_column(Integer)
    region: Mapped[str] = mapped_column(String)
    entryFee: Mapped[str] = mapped_column(String)
    tournamentid: Mapped[str] = mapped_column(String,default=igen(8))
    image: Mapped[str] = mapped_column(String, default="original.jpg")
    description: Mapped[str] = mapped_column(String)
    rules: Mapped[str] = mapped_column(String, default="None")
    registrationDeadline: Mapped[str] = mapped_column(String, default="None")
    groupStages: Mapped[str] = mapped_column(String, default="None")
    semiFinals: Mapped[str] = mapped_column(String, default="None")
    finals: Mapped[str] = mapped_column(String, default="None")
    prize1: Mapped[str] = mapped_column(String, default="0")
    prize2: Mapped[str] = mapped_column(String, default="0")
    prize3: Mapped[str] = mapped_column(String, default="0")
    allowTeams: Mapped[str] = mapped_column(String, default="no")
    comission: Mapped[str] = mapped_column(String, default="0")
    roomCode: Mapped[str] = mapped_column(String, default="Yet to be announced!")

class tournamentRegistration(database.Model):
    """
    Represents the tournament registration table in the database.
    """
    num: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tournamentid: Mapped[str] = mapped_column(String)
    username: Mapped[str] = mapped_column(String)
    userId: Mapped[str] = mapped_column(String)
    teamName: Mapped[str] = mapped_column(String, default="None")
    teamCount: Mapped[int] = mapped_column(Integer, default=0)
    teamMember1: Mapped[str] = mapped_column(String, default="None")
    teamMember2: Mapped[str] = mapped_column(String, default="None")
    teamMember3: Mapped[str] = mapped_column(String, default="None")
    teamMember4: Mapped[str] = mapped_column(String, default="None")
    teamMember5: Mapped[str] = mapped_column(String, default="None")
    status: Mapped[str] = mapped_column(String, default="Registered")
    createdAt: Mapped[str] = mapped_column(String, default=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    editValidity: Mapped[str] = mapped_column(String, default="None")

class userWallet(database.Model):
    """
    Represents the user wallet table in the database.
    """
    num: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    walletId: Mapped[str] = mapped_column(String, default=igen(8))
    userId: Mapped[str] = mapped_column(String, default=igen(8))
    balance: Mapped[int] = mapped_column(Integer, default=0)
    createdAt: Mapped[str] = mapped_column(String, default=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

class transactions(database.Model):
    """
    Represents the transactions table in the database.
    """
    num: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    transactionId: Mapped[str] = mapped_column(String)
    userWalletId: Mapped[str] = mapped_column(String)
    orderReceipt: Mapped[str] = mapped_column(String)
    userId: Mapped[str] = mapped_column(String)
    amount: Mapped[int] = mapped_column(Integer)
    type: Mapped[str] = mapped_column(String, default="deposit")
    status: Mapped[str] = mapped_column(String, default="pending")
    description: Mapped[str] = mapped_column(String, default="Wallet Deposit")
    createdAt: Mapped[str] = mapped_column(String, default=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


class tournamentWinners(database.Model):
    """
    Represents the tournament winners table in the database.
    """
    num: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tournamentid: Mapped[str] = mapped_column(String)
    winner1: Mapped[str] = mapped_column(String, default="None")
    winner2: Mapped[str] = mapped_column(String, default="None")
    winner3: Mapped[str] = mapped_column(String, default="None")
    createdAt: Mapped[str] = mapped_column(String, default=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

class scoresheet(database.Model):
    """
    Represents the scoresheet table in the database.
    """
    num: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tournamentid: Mapped[str] = mapped_column(String)
    scoresheetid: Mapped[str] = mapped_column(String, default=igen(8))
    participant1: Mapped[str] = mapped_column(String, default="None")
    participant2: Mapped[str] = mapped_column(String, default="None")
    participantScore1: Mapped[int] = mapped_column(Integer, default=0)
    participantScore2: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String, default="live")
    createdAt: Mapped[str] = mapped_column(String, default=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

class auditLog(database.Model):
    """
    Represents the audit log table in the database.
    """
    num: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    action: Mapped[str] = mapped_column(String)
    userId: Mapped[str] = mapped_column(String)
    timestamp: Mapped[str] = mapped_column(String, default=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    details: Mapped[str] = mapped_column(String, default="None")


def autoSettle(tournamentid):
    """
        Incase tournament fails to reach the mark of prizePool, this function will automatically adjust the prizePool, commision and prizes based of their orignial percentage distribution
    """
    tournament = tournamentInfo.query.filter_by(tournamentid=tournamentid).first()
    registrations = tournamentRegistration.query.filter_by(tournamentid=tournamentid).count()
    oldPool = int(tournament.prizePool)
    if registrations < tournament.maxParticipants:
        if oldPool > 0:
            newPool = int(tournament.entryFee) * registrations
            tournament.prizePool = str(newPool)
            arrayNew = [int(newPool * (int(tournament.prize1)/oldPool)), int(newPool * (int(tournament.prize2)/oldPool)), int(newPool * (int(tournament.prize3)/oldPool))]
            tournament.prize1 = str(arrayNew[0])
            tournament.prize2 = str(arrayNew[1])
            tournament.prize3 = str(arrayNew[2])
            database.session.commit()
        
            return True
    return False

def autoAudit(action: str, userId: str, details: str = "None"):
    """
    Automatically logs actions performed by users in the audit log.
    """
    new_log = auditLog(action=action, userId=userId, details=details)
    database.session.add(new_log)
    database.session.commit()


@app.route('/')
def home():
    tournaments_list = tournamentInfo.query.filter(tournamentInfo.status != 'deleted').all()
    return render_template('index.html',tournaments=tournaments_list)

@app.route('/admin/')
def adminHome():
    if 'admin' in session:
        autoAudit('Admin Accessed Admin Panel', session['admin'])
        return render_template('admin.html')
    else:
        return redirect(url_for('adminlogin'))

@app.route('/tournaments/')
def tournaments():
    tournaments_list = tournamentInfo.query.filter(tournamentInfo.status!='deleted').all()
    return render_template('tournaments.html',tournaments=tournaments_list)

@app.route('/auth/')
def auth():
    if 'user' in session:
        return redirect(url_for('user_profile'))
    autoAudit('User Accessed Auth Page', session.get('userid', 'Guest'))
    return render_template('auth.html')

@app.route('/api/<path>/',methods=['POST'])
def apiv1(path):
    if path == 'signup':
        autoAudit('User Attempted Signup', session.get('userid', 'Guest'))
        data = request.get_json()
        if data:
            username = data.get('username')
            email = data.get('email')
            password = password_hash(data.get('password'))

            check_user = users.query.filter_by(username = username).first()
            if check_user:
                return {'response': 400, 'message': 'Username already exists'}
            check_email = users.query.filter_by(email = email).first()
            if check_email:
                return {'response': 400, 'message': 'Email already exists'}

            if username and email and password:
                userid = igen(8)
                new_user = users(username=username, email=email, password=password, userid=userid)
                new_wallet = userWallet(userId=userid)
                database.session.add(new_wallet)
                database.session.add(new_user)
                database.session.commit()
                autoAudit('User Signed Up', userid, f'Username: {username}, Email: {email}')
                return {'response': 200, 'message': 'Account created successfully!'}
            else:
                return {'response': 400, 'message': 'Invalid input'}
        else:
            return {'response': 400, 'message': 'Invalid input'}
    elif path == 'login':
        data = request.get_json()
        autoAudit('User Attempted Login', session.get('userid', 'Guest'))
        if data:
            username = data.get('email')
            password = password_hash(data.get('password'))
            
            if username.find('@') != -1:
                user = users.query.filter_by(email=username, password=password).first()
            else:
                user = users.query.filter_by(username=username, password=password).first()
            
            
            if user:
                session['user'] = user.username
                session['userid'] = user.userid
                autoAudit('User Logged In', user.userid, f'Username: {user.username}, Email: {user.email}')
                return {'response': 200, 'message': 'Login successful!'}
            else:
                autoAudit('User Login Failed', session.get('userid', 'Guest'), f'Username: {username}')
                return {'response': 400, 'message': 'Invalid credentials'}
        else:
            return {'response': 400, 'message': 'Invalid input'}
    elif path == 'addtournament':
        if 'user' not in session:
            return {'response': 403, 'message': 'User not logged in'}
        autoAudit('User Attempted to Add Tournament', session['userid'])
        data = request.get_json()

        if data:
            host = session['userid']

            totalHosted = tournamentInfo.query.filter_by(host=host).count()
            if totalHosted > 3:
                autoAudit('User Exceeded Tournament Hosting Limit', host)
                return {'response': 400, 'message': 'You can only host a maximum of 3 tournaments at a time.'}

            title = data.get('title')
            status = data.get('status')
            gameType = data.get('gameType')
            startDate = data.get('startDate')
            endDate = data.get('endDate')
            gameFormat = data.get('gameFormat')
            prizePool = data.get('prizePool')
            participantsCount = data.get('participantsCount')
            maxParticipants = data.get('maxParticipants')
            region = data.get('region')
            entryFee = str(data.get('entryFee','0'))
            description = data.get('description')
            rules = data.get('rules')
            registrationDeadline = data.get('registrationDeadline')
            groupStages = data.get('groupStages')
            semiFinals = data.get('semiFinals')
            finals = data.get('finals')
            prize1 = data.get('prize1', '0')
            prize2 = data.get('prize2', '0')
            prize3 = data.get('prize3', '0')
             

            if title and status and gameType and startDate and endDate and gameFormat and prizePool and participantsCount is not None and maxParticipants is not None and region and entryFee and prize1 and prize2 and prize3:
                tournamentid = igen(8)
                if int(prizePool) - (int(prize1) + int(prize2) + int(prize3)) != 0:
                    return {'response': 400, 'message': 'Prize pool does not match the sum of individual prizes'}
                if int(participantsCount) > int(maxParticipants):
                    return {'response': 400, 'message': 'Participants count cannot be greater than maximum participants'}
                if int(prize1) < 0 or int(prize2) < 0 or int(prize3) < 0:
                    return {'response': 400, 'message': 'Prize values cannot be negative'}
                if int(prize1) > int(prizePool) or int(prize2) > int(prizePool) or int(prize3) > int(prizePool):
                    return {'response': 400, 'message': 'Prize values cannot be greater than prize pool'}
                if int(entryFee) < 0:
                    return {'response': 400, 'message': 'Entry fee cannot be negative'}
                if int(maxParticipants) < 2:
                    return {'response': 400, 'message': 'Maximum participants must be at least 2'}
                

                new_tournament = tournamentInfo(host=host, title=title, status=status, gameType=gameType, startDate=startDate, endDate=endDate, gameFormat=gameFormat, prizePool=prizePool, participantsCount=participantsCount, maxParticipants=maxParticipants, region=region, entryFee=entryFee, description=description, rules=rules, registrationDeadline=registrationDeadline, groupStages=groupStages, semiFinals=semiFinals, finals=finals, tournamentid=tournamentid, prize1=prize1, prize2=prize2, prize3=prize3, comission='0')
                database.session.add(new_tournament)
                autoAudit('User Added Tournament', host, f'Tournament ID: {tournamentid}, Title: {title}, Host: {host}')
                database.session.commit()
                return {'response': 200, 'message': tournamentid}
            else:
                return {'response': 400, 'message': 'Invalid input data'}
        else:
            return {'response': 400, 'message': 'Invalid input'}
    elif path == 'edittournament':
        if 'user' not in session:
            return {'response': 403, 'message': 'User not logged in'}
        data = request.get_json()
        additionalMessage = ''
        if data:
            tournamentid = data.get('tournamentid')
            tournament = tournamentInfo.query.filter_by(tournamentid=tournamentid).first()
            if tournament and tournament.host == session['userid']:

                tournament.status = data.get('status', tournament.status)

                tournament.startDate = data.get('startDate', tournament.startDate)
                tournament.endDate = data.get('endDate', tournament.endDate)
                tournament.gameFormat = data.get('gameFormat', tournament.gameFormat)

                tournament.participantsCount = data.get('participantsCount', tournament.participantsCount)
                tournament.maxParticipants = data.get('maxParticipants', tournament.maxParticipants)
                tournament.region = data.get('region', tournament.region)

                tournament.description = data.get('description', tournament.description)
                tournament.rules = data.get('rules', tournament.rules)
                tournament.registrationDeadline = data.get('registrationDeadline', tournament.registrationDeadline)
                tournament.groupStages = data.get('groupStages', tournament.groupStages)
                tournament.semiFinals = data.get('semiFinals', tournament.semiFinals)
                tournament.finals = data.get('finals', tournament.finals)
                
                autoAudit('User Edited Tournament', session['userid'], f'Tournament ID: {tournamentid}, Title: {tournament.title}')
                database.session.commit()
                return {'response': 200, 'message': 'Tournament updated successfully!'}
            else:
                return {'response': 403, 'message': 'User not authorized to update this tournament'}
        else:
            return {'response': 400, 'message': 'Invalid input'}
    elif path == 'toggleteams':
        if 'user' not in session:
            return {'response': 403, 'message': 'User not logged in'}
        data = request.get_json()
        if data:
            tournamentid = data.get('tournamentid')
            tournament = tournamentInfo.query.filter_by(tournamentid=tournamentid).first()
            if tournament and tournament.host == session['userid']:
                if tournament.allowTeams == 'yes':
                    tournament.allowTeams = 'no'  
                else:
                    tournament.allowTeams = 'yes'
                database.session.commit()
                autoAudit('User Toggled Team Mode', session['userid'], f'Tournament ID: {tournamentid}, Title: {tournament.title}, New Team Mode: {tournament.allowTeams}')
                return {'response': 200, 'message': 'Tournament team mode updated successfully!'}
            else:
                return {'response': 403, 'message': 'User not authorized to update this tournament'}
        else:
            return {'response': 400, 'message': 'Invalid input'}
        
    elif path == 'uploadbanner':
        if 'user' not in session:
            return {'response': 403, 'message': 'User not logged in'}
        picture = request.files.get('image')
        tournamentid = request.form.get('id')
        if picture and tournamentid:
            ext = picture.filename.split('.')[-1].lower()
            if ext in ALLOWED_EXTENSIONS:
                filename = f"{tournamentid}.{ext}"
                file_path = os.path.join(UPLOAD_FOLDER, filename)
                if os.path.exists(file_path):
                    os.remove(file_path)
                picture.save(f"{UPLOAD_FOLDER}/{filename}")
                tournament = tournamentInfo.query.filter_by(tournamentid=tournamentid).first()
                if tournament and tournament.host == session['userid']:
                    tournament.image = filename
                    database.session.commit()
                    return {'response': 200, 'message': 'Banner uploaded successfully!'}
                else:
                    return {'response': 403, 'message': 'User not authorized to update this tournament'}
            else:
                return {'response': 400, 'message': 'Invalid file type'}
        else:
            return {'response': 400, 'message': 'No file or tournament ID provided'}
            
    elif path == 'updateprofile':
        if 'user' not in session:
            return {'response': 403, 'message': 'User not logged in'}
        data = request.get_json()
        if data.get('type') == 'info':
            username = data.get('username')
            bio = data.get('bio')
            gamerExperience = data.get('experience')
            user = users.query.filter_by(username=session['user']).first()
            if user:
                session['user'] = username
                user.username = username
                user.bio = bio
                user.gamerExperience = gamerExperience
                database.session.commit()
                autoAudit('User Updated Profile', session['userid'], f'Username: {username}, Bio: {bio}, Experience: {gamerExperience}')
                return {'response': 200, 'message': 'Profile updated successfully!'}
            else:
                return {'response': 400, 'message': 'User not found'}
        elif data.get('type') == 'password':
            data = request.get_json()
            if data:
                oldPassword = password_hash(data.get('oldPassword'))
                newPassword = password_hash(data.get('newPassword'))
                user = users.query.filter_by(username=session['user'], password=oldPassword).first()
                if user:
                    user.password = newPassword
                    database.session.commit()
                    autoAudit('User Updated Password', session['userid'], f'Username: {user.username}')
                    return {'response': 200, 'message': 'Password updated successfully!'}
                else:
                    return {'response': 400, 'message': 'Invalid old password'}
            else:
                return {'response': 400, 'message': 'Invalid input'}
        else:
            return {'response': 400, 'message': 'Invalid input'}
    elif path == 'delete':
        if 'user' not in session:
            return {'response': 403, 'message': 'User not logged in'}
        data = request.get_json()
        action = data.get('action')
        if action == 'tournament':
            tournamentid = data.get('tournamentid')
            tournament = tournamentInfo.query.filter_by(tournamentid=tournamentid).first()
            
            if tournament and tournament.host == session['userid']:
                
                registrations = tournamentRegistration.query.filter_by(tournamentid=tournamentid).all()
                for registration in registrations:
                    registration.status = 'Cancelled'
                    wallet = userWallet.query.filter_by(userId=registration.userId).first()
                    if wallet:
                        wallet.balance += int(tournament.entryFee)
                        transaction = transactions(userId=registration.userId, userWalletId=wallet.walletId, amount=int(tournament.entryFee), type='deposit', status='Success', description=f'Refund for cancelled tournament {tournament.title}', orderReceipt=igen(8), transactionId=igen(8))
                        database.session.add(transaction)

                database.session.delete(tournament)
                database.session.commit()
                autoAudit('User Deleted Tournament', session['userid'], f'Tournament ID: {tournamentid}, Title: {tournament.title}')
                return {'response': 200, 'message': 'Tournament deleted successfully!'}
            else:
                return {'response': 403, 'message': 'User not authorized to delete this tournament'}

    elif path == 'payment':
        if 'user' not in session:
            return {'response': 403, 'message': 'User not logged in'}
        data = request.get_json()
        action = data.get('action')
        if action == 'create_order':
            amount = data.get('amount')
            userId = session['userid']
            checkTransaction = transactions.query.filter_by(userId=userId, status='pending').count()
            autoAudit('User Attempted to Create Payment Order', userId, f'Amount: {amount}')
            if checkTransaction > 2:
                return {'response': 400, 'message': 'You already have few pending transaction. Please wait for them to settle try after 15 minutes.'}
            
            if amount and userId:
                order_amount = int(amount)  * 100 # Amount in paise
                order_currency = 'INR'
                order_receipt = igen(8)
                orderData = {"amount": order_amount, "currency": order_currency, "receipt": order_receipt}
                
                order = paymentClient.order.create(data=orderData)
                wallet = userWallet.query.filter_by(userId=userId).first()
                transaction = transactions(orderReceipt=order_receipt, transactionId=order['id'], userWalletId=wallet.walletId, userId=userId, amount=amount)
                database.session.add(transaction)
                database.session.commit()
                autoAudit('User Created Payment Order', userId, f'Order ID: {order["id"]}, Amount: {amount}')
                return {'response': 200, 'message': 'Order created successfully!', 'orderid': order['id'], 'amount': amount,'key_id':os.getenv('RZP_API')}
            else:
                return {'response': 400, 'message': 'Invalid input data'}
    elif path == 'paysuccess':
        paymentId=request.form.get("razorpay_payment_id")
        orderId=request.form.get("razorpay_order_id")
        sign=request.form.get("razorpay_signature")
    
        params={
            'razorpay_order_id': orderId,
            'razorpay_payment_id': paymentId,
            'razorpay_signature': sign
        }
        final= paymentClient.utility.verify_payment_signature(params)
        if final == True:
            wallet = userWallet.query.filter_by(userId=session['userid']).first()
            if not wallet:
                wallet = userWallet(userId=session['userid'])
                database.session.add(wallet)
                database.session.commit()

            
            transaction = transactions.query.filter_by(transactionId=orderId).first()
            if transaction:
                transaction.status = "Success"
                wallet.balance += transaction.amount
                database.session.commit()
                autoAudit('User Payment Successful', session['userid'], f'Order ID: {orderId}, Amount: {transaction.amount}')
                return redirect(f'/wallet/?toast=Payment successful!')
            else:
                return "Transaction not found"
        else:
            transaction = transactions.query.filter_by(transactionId=orderId).first()
            if transaction:
                transaction.status = "Failed"
                database.session.commit()
                autoAudit('User Payment Failed', session['userid'], f'Order ID: {orderId}, Amount: {transaction.amount}')
                return "Payment verification failed"
            else:
                return "Transaction not found!"
    elif path == 'tournamentregister':
        if 'user' not in session:
            return {'response': 403, 'message': 'User not logged in'}
        data = request.get_json()
        autoAudit('User Attempted to Register for Tournament', session.get('userid', 'Guest'))
        if data:
            tournamentid = data.get('tournamentid')
            tournament = tournamentInfo.query.filter_by(tournamentid=tournamentid).first()

            team = data.get('team', 'no')
            if team == 'yes':
                autoAudit('User Attempted to Register for Team Tournament', session.get('userid', 'Guest'))
                if tournament.allowTeams == 'no':
                    return {'response': 400, 'message': 'Teams are not allowed for this tournament'}
                teamName = data.get('teamName',None)
                teamMembers_count = data.get('memberCount', 0)
                teamMembers = data.get('team_members')
                if not teamName or not teamMembers or len(teamMembers) != int(teamMembers_count):
                    return {'response': 400, 'message': 'Invalid input'}
                checkTeam = tournamentRegistration.query.filter_by(tournamentid=tournamentid, teamName=teamName).first()
                if checkTeam:
                    return {'response': 400, 'message': 'Team name already exists'}
                    
                try:
                    if int(teamMembers_count) < 1 or int(teamMembers_count) > 5:
                        return {'response': 400, 'message': 'Invalid number of team members'}
                except:
                    return {'response': 400, 'message': 'Invalid number of team members'}
                
                memeberVariables = {'member1': '', 'member2': '', 'member3': '', 'member4': '', 'member5': ''}

                for i in range(int(teamMembers_count)):
                    memeberVariables[f'member{i+1}'] = teamMembers[i]

            

            if tournament:
                autoAudit('User Attempted to Register for Tournament', session['userid'], f'Tournament ID: {tournamentid}, Title: {tournament.title}')
                if tournament.participantsCount < tournament.maxParticipants:
                    checkRegistration = tournamentRegistration.query.filter_by(tournamentid=tournamentid, userId=session['userid']).first()
                    if checkRegistration:
                        return {'response': 400, 'message': 'You are already registered for this tournament'}
                    wallet = userWallet.query.filter_by(userId=session['userid']).first()
                    if not wallet:
                        wallet = userWallet(userId=session['userid'])
                        database.session.add(wallet)
                        database.session.commit()
                    entryFee = int(tournament.entryFee)
                    if tournament.entryFee != '0':
                        if wallet.balance < entryFee:
                            return {'response': 400, 'message': 'Insufficient balance in wallet'}
                        else:
                            wallet.balance -= entryFee
                    transaction = transactions(userId=session['userid'], userWalletId=wallet.walletId, amount=entryFee, type='withdrawal', status='Success', description=f'Entry fee for tournament {tournament.title}', orderReceipt=igen(8), transactionId=igen(8))
                    username = session['user']
                    userId = session['userid']
                    if team == 'yes' and int(teamMembers_count) > 0 and tournament.allowTeams == 'yes': 
                        registration = tournamentRegistration(tournamentid=tournamentid, username=username, userId=userId, teamCount=int(teamMembers_count), teamName=teamName, teamMember1=memeberVariables['member1'], teamMember2=memeberVariables['member2'], teamMember3=memeberVariables['member3'], teamMember4=memeberVariables['member4'], teamMember5=memeberVariables['member5'], editValidity=tournament.registrationDeadline)
                    else:
                        registration = tournamentRegistration(tournamentid=tournamentid, username=username, userId=userId, editValidity=tournament.registrationDeadline)
                    database.session.add(registration)
                    database.session.add(transaction)
                    tournament.participantsCount += 1
                    if int(tournament.entryFee)*int(tournament.participantsCount) >= int(tournament.prizePool):
                        tournament.comission = str(int(tournament.entryFee) * tournament.participantsCount - int(tournament.prizePool))

                    database.session.commit()
                    autoAudit('User Registered for Tournament', session['userid'], f'Tournament ID: {tournamentid}, Title: {tournament.title}, Team: {teamName if team == "yes" else "Individual"}')
                    return {'response': 200, 'message': 'Registered successfully!'}
                else:
                    autoAudit('User Registration Failed for Tournament', session['userid'], f'Tournament ID: {tournamentid}, Title: {tournament.title}, Reason: Tournament is full')
                    return {'response': 400, 'message': 'Tournament is full'}
            else:
                return {'response': 400, 'message': 'Tournament not found'}
        else:
            return {'response': 400, 'message': 'Invalid input'}
        
    elif path == 'updateteams':
        if 'user' not in session:
            return {'response': 403, 'message': 'User not logged in'}
        data = request.get_json()
        autoAudit('User Attempted to Update Team', session.get('userid', 'Guest'))
        if data:
            tournamentid = data.get('tournamentid')
            teamMembers_count = data.get('memberCount', 0)
            teamName = data.get('teamName', None)
            teamMembers = data.get('members', [])
            
            if not tournamentid or not teamMembers or len(teamMembers) != int(teamMembers_count) or not teamName:
                return {'response': 400, 'message': 'Invalid input'}
            tournament = tournamentRegistration.query.filter_by(tournamentid=tournamentid, userId=session['userid']).first()
            if tournament:
                if int(teamMembers_count) < 1 or int(teamMembers_count) > 5:
                    return {'response': 400, 'message': 'Invalid number of team members'}
                memeberVariables = {'member1': '', 'member2': '', 'member3': '', 'member4': '', 'member5': ''}

                for i in range(int(teamMembers_count)):
                    memeberVariables[f'member{i+1}'] = teamMembers[i]

                tournament.teamCount = int(teamMembers_count)
                tournament.teamMember1 = memeberVariables['member1']
                tournament.teamMember2 = memeberVariables['member2']
                tournament.teamMember3 = memeberVariables['member3']
                tournament.teamMember4 = memeberVariables['member4']
                tournament.teamMember5 = memeberVariables['member5']
                database.session.commit()
                autoAudit('User Updated Team', session['userid'], f'Tournament ID: {tournamentid}, Team Name: {teamName}, Members: {teamMembers}')
                return {'response': 200, 'message': 'Team updated successfully!'}
            else:
                return {'response': 400, 'message': 'Team not found or user not authorized to update this team'}
        else:
            return {'response': 400, 'message': 'Invalid input'}

    elif path == 'roomcode':
        if 'user' not in session:
            return {'response': 403, 'message': 'User not logged in'}
        data = request.get_json()
        if data:
            tournamentid = data.get('tournamentid')
            roomCode = data.get('room')
            tournament = tournamentInfo.query.filter_by(tournamentid=tournamentid).first()
            if tournament and tournament.host == session['userid']:
                tournament.roomCode = roomCode
                database.session.commit()
                autoAudit('User Updated Room Code', session['userid'], f'Tournament ID: {tournamentid}, Room Code: {roomCode}')
                return {'response': 200, 'message': 'Room code updated successfully!'}
            else:
                return {'response': 403, 'message': 'User not authorized to update this tournament'}
        else:
            return {'response': 400, 'message': 'Invalid input'}
    elif path == 'participantstats':
        if 'user' not in session:
            return {'response': 403, 'message': 'User not logged in'}
        data = request.get_json()
        if data:
            tournamentid = data.get('tournamentid')
            userId = data.get('userId')
            status = data.get('status')
            position = data.get('position', None)
            reason = data.get('reason', None)
            tournamentInformation = tournamentInfo.query.filter_by(tournamentid=tournamentid).first()
            tournament = tournamentRegistration.query.filter_by(tournamentid=tournamentid, userId=userId).first()
            if tournament and tournament.userId == session['userid']:
                user = users.query.filter_by(userid=userId).first()
                tournament.status = f"{status} at {position}th position" + (f" due to {reason}" if reason else "")
                if position >= 3:
                    wallet = userWallet.query.filter_by(userId=userId).first()
                    user.tournamentsWon += 1
                    checkWinnerList = tournamentWinners.query.filter_by(tournamentid=tournamentid).first()
                    if not checkWinnerList:
                        winnerList = tournamentWinners(tournamentid=tournamentid)
                        database.session.add(winnerList)
                    
                    if position == 1:
                        checkWinnerList.winner1 = user.username
                        tournamentInformation.prize1 = tournamentInformation.prize1 if tournamentInformation.prize1 != '0' else '0'
                        user.totalEarnings += int(tournamentInformation.prize1)
                        wallet.balance += int(tournamentInformation.prize1)
                        tournament.status = f"{status}"

                    elif position == 2:
                        checkWinnerList.winner2 = user.username
                        tournamentInformation.prize2 = tournamentInformation.prize2 if tournamentInformation.prize2 != '0' else '0'
                        user.totalEarnings += int(tournamentInformation.prize2)
                        wallet.balance += int(tournamentInformation.prize2)
                        tournament.status = f"{status}"


                    elif position == 3:
                        checkWinnerList.winner3 = user.username
                        tournamentInformation.prize3 = tournamentInformation.prize3 if tournamentInformation.prize3 != '0' else '0'
                        user.totalEarnings += int(tournamentInformation.prize3)
                        wallet.balance += int(tournamentInformation.prize3)
                        tournament.status = f"{status}"


                user.tournamentsPlayed += 1
                user.bestRank = position if user.bestRank == 0 or position >= user.bestRank else user.bestRank
                database.session.commit()
                autoAudit('User Updated Participant Stats', session['userid'], f'Tournament ID: {tournamentid}, User: {user.username}, Status: {tournament.status}')
                return {'response': 200, 'message': 'Status updated successfully!'}
            else:
                return {'response': 403, 'message': 'User not authorized to update this tournament'}
        else:
            return {'response': 400, 'message': 'Invalid input'}
    elif path == 'scoresheet':
        if 'user' not in session:
            return {'response': 403, 'message': 'User not logged in'}
        data = request.get_json()
        if data:
            tournamentid = data.get('tournamentid')
            checkTournament = tournamentInfo.query.filter_by(tournamentid=tournamentid).first()
            if not checkTournament:
                return {'response': 400, 'message': 'Tournament not found'}
            if checkTournament.host != session['userid']:
                return {'response': 403, 'message': 'User not authorized to update this tournament'}
            participant1 = data.get('participant1')
            participant2 = data.get('participant2')
            participantScore1 = data.get('score1', 0)
            participantScore2 = data.get('score2', 0)
            scoresheetid = data.get('uid', igen(8))

            checkScoresheet = scoresheet.query.filter_by(scoresheetid=scoresheetid).first()

            if not checkScoresheet:
                scoresheetEntry = scoresheet(tournamentid=tournamentid, scoresheetid=scoresheetid, participant1=participant1, participant2=participant2, participantScore1=participantScore1, participantScore2=participantScore2)
                database.session.add(scoresheetEntry)
                database.session.commit()
                autoAudit('User Created Scoresheet', session['userid'], f'Tournament ID: {tournamentid}, Scoresheet ID: {scoresheetid}, Participant1: {participant1}, Participant2: {participant2}')
                return {'response': 200, 'message': 'Scoresheet created successfully!'}
            elif checkScoresheet and checkScoresheet.status == 'live':
                checkScoresheet.participant1 = participant1
                checkScoresheet.participant2 = participant2
                checkScoresheet.participantScore1 = participantScore1
                checkScoresheet.participantScore2 = participantScore2
                database.session.commit()
                autoAudit('User Updated Scoresheet', session['userid'], f'Tournament ID: {tournamentid}, Scoresheet ID: {scoresheetid}, Participant1: {participant1}, Participant2: {participant2}')
                return {'response': 200, 'message': 'Scoresheet updated successfully!'}
            elif checkScoresheet and checkScoresheet.status == 'completed':
                return {'response': 400, 'message': 'Scoresheet already completed'}
            else:
                return {'response': 400, 'message': 'Invalid input'}
        else:
            return {'response': 400, 'message': 'Invalid input'}
    elif path == 'withdrawal':
        autoAudit('User Attempted Withdrawal', session.get('userid', 'Guest'))
        if 'user' not in session:
            return {'response': 403, 'message': 'User not logged in'}
        data = request.get_json()
        if data:
            userId = session['userid']
            amount = data.get('amount')
            paymentData = {'payeeName'  : data.get('payeeName'), 'accountNumber' :data.get('accountNumber'), 'ifscCode' :data.get('ifscCode'), 'mobileNumber'  :data.get('mobileNumber')}
            reason = str(paymentData)

            if not amount or not reason:
                return {'response': 400, 'message': 'Invalid input'}
            wallet = userWallet.query.filter_by(userId=userId).first()
            if not wallet:
                return {'response': 400, 'message': 'Wallet not found'}
            if wallet.balance < int(amount):
                return {'response': 400, 'message': 'Insufficient balance in wallet'}
            transaction = transactions(userId=userId, userWalletId=wallet.walletId, amount=amount, type='withdrawal', status='pending', description=reason, orderReceipt=igen(8), transactionId=igen(8))
            database.session.add(transaction)
            database.session.commit()
            autoAudit('User Created Withdrawal Request', userId, f'Amount: {amount}, Reason: {reason}')
            return {'response': 200, 'message': 'Withdrawal request created successfully!'}

@app.route('/admin/api/<path>/',methods=['POST'])
def apiv2(path):
    if path == 'login':
        data = request.get_json()
        if data:
            username = data.get('username')
            password = password_hash(data.get('password'))
            if username == adminClinet and password == adminPassword:
                session['admin'] = True
                autoAudit('Admin Logged In', 'Admin', f'Username: {username}')
                return {'response': 200, 'message': 'Login successful!'}
            else:
                return {'response': 400, 'message': 'Invalid credentials'}
        else:
            return {'response': 400, 'message': 'Invalid input'}
    elif path == 'logout':
        autoAudit('Admin Logged Out', 'Admin', 'Admin logged out successfully')
        session.pop('admin', None)
        return {'response': 200, 'message': 'Logged out successfully'}


    elif path == 'appraisal':
        if 'admin' not in session:
            return redirect(url_for('adminlogin'))
        data = request.get_json()
        transactionId = data.get('transactionId')
        action = data.get('action')
        reason = data.get('reason', None)
        autoAudit('Admin Attempted to Appraise Withdrawal', 'Admin', f'Transaction ID: {transactionId}, Action: {action}, Reason: {reason}')
        if not transactionId:
            return {'response': 400, 'message': 'Transaction ID is required'}
        
        if action == 'done':
            transaction = transactions.query.filter_by(transactionId=transactionId, status='pending').first()
            if transaction:
                transaction.status = 'Success'
                transaction.type = 'withdrawal'
                transaction.description = f" Approved for withdrawal on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} will take 2-3 business days to process."
                autoAudit('Admin Withdrawal Approval', 'Admin', f'Transaction ID: {transactionId}, Amount: {transaction.amount}')
                wallet = userWallet.query.filter_by(userId=transaction.userId).first()
                if wallet:
                    if wallet.balance is None:
                        wallet.balance = 0
                    if wallet.balance < transaction.amount:
                        autoAudit('Admin Withdrawal Approval Failed', 'Admin', f'Transaction ID: {transactionId}, Reason: Insufficient balance in wallet')
                        return {'response': 400, 'message': 'Insufficient balance in wallet'}
                    wallet.balance -= transaction.amount
                database.session.commit()
                autoAudit('Admin Withdrawal Approved', 'Admin', f'Transaction ID: {transactionId}, Amount: {transaction.amount}')
                return {'response': 200, 'message': 'Withdrawal request approved successfully!'}
            else:
                return {'response': 400, 'message': 'Transaction not found!'}
        elif action == 'reject':
            transaction = transactions.query.filter_by(transactionId=transactionId, status='pending').first()
            if transaction:
                transaction.status = 'failed'
                transaction.type = 'withdrawal'
                if reason:
                    transaction.description = f" Rejected due to: {reason}"
                database.session.commit()
                autoAudit('Admin Withdrawal Rejected', 'Admin', f'Transaction ID: {transactionId}, Reason: {reason}')
                return {'response': 200, 'message': 'Withdrawal request rejected successfully!'}
            else:
                return {'response': 400, 'message': 'Transaction not found!'}

    elif path == 'delete':
        if 'admin' not in session:    
            return redirect(url_for('adminlogin'))
        
        data = request.get_json()
        autoAudit('Admin Attempted to Delete Tournament', 'Admin', f'Tournament ID: {data.get("tournamentid")}')
        tournamentid = data.get('tournamentid', None)
        tournament = tournamentInfo.query.filter_by(tournamentid=tournamentid).first()
        if tournament:
            registrations = tournamentRegistration.query.filter_by(tournamentid=tournamentid).all()
            for registration in registrations:
                registration.status = 'Cancelled'
                wallet = userWallet.query.filter_by(userId=registration.userId).first()
                if wallet:
                    autoAudit('Admin Refunded Tournament Entry Fee', 'Admin', f'Tournament ID: {tournamentid}, User ID: {registration.userId}, Amount: {tournament.entryFee}')
                    wallet.balance += int(tournament.entryFee)
                    transaction = transactions(userId=registration.userId, userWalletId=wallet.walletId, amount=int(tournament.entryFee), type='deposit', status='Success', description=f'Refund for cancelled tournament {tournament.title}', orderReceipt=igen(8), transactionId=igen(8))
                    database.session.add(transaction)

            tournament.status = 'deleted'
            tournament.title = f"{tournament.title} (Deleted)"
            tournament.host += '[deleted]'
            tournament.description += f'This tournament has been deleted by the admin. \n due to {data.get("reason", "No reason provided")}'
            database.session.commit()
            autoAudit('Admin Deleted Tournament', 'Admin', f'Tournament ID: {tournamentid}, Title: {tournament.title}')
            return {'response': 200, 'message': 'Tournament deleted successfully!'}
        
        
        
        


@app.route('/audit/')
def audit():
    if 'admin' not in session:
        return redirect(url_for('adminlogin'))
    
    audit_logs = auditLog.query.order_by(auditLog.timestamp.desc()).all()
    return render_template('audit.html', audit_logs=audit_logs)



@app.route('/admin/login/')
def adminlogin():
    if 'admin' in session:
        return redirect(url_for('adminHome'))
    autoAudit('Admin Accessed Login Page', 'Admin', 'Admin login page accessed')
    return render_template('adminlogin.html')

@app.route('/admintor/')
def admin_tournaments():
    if 'admin' in session:
        tournaments_list = tournamentInfo.query.all()
        return render_template('admintor.html', tournaments=tournaments_list)
    else:
        return redirect(url_for('adminlogin'))


@app.route('/logout/')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))

@app.route('/details/')
def tournament_details():
    tourId = request.args.get('tournamentid', None)
    autoAudit('User Accessed Tournament Details', session.get('userid', 'Guest'), f'Tournament ID: {tourId}')
    tournament = None
    if tourId != None:
        tournament = tournamentInfo.query.filter_by(tournamentid=tourId).first()
        
        if tournament:
            registrations = tournamentRegistration.query.filter_by(tournamentid=tourId).all()
            scores = scoresheet.query.filter_by(tournamentid=tourId).all()
            registered = []
            isUserRegistered = False
            if registrations and len(registrations) > 0 and 'user' in session:
                for registration in registrations:
                    if registration.userId == session['userid']:
                        isUserRegistered = True
                    user = users.query.filter_by(userid=registration.userId).first()
                    registration.username = user.username if user else "Unknown User"
                    registration.createdAt = registration.createdAt
                    registration.teamName = registration.teamName if registration.teamName != "None" else "No Team"
                    registration.teamMembers = [registration.teamMember1, registration.teamMember2, registration.teamMember3, registration.teamMember4, registration.teamMember5]
                    registered.append(registration)
            
            hostUser = users.query.filter_by(userid=tournament.host).first()
            
            return render_template('tournamentsdetails.html', tournament=tournament, hostUser=hostUser,registered=registered, isUserRegistered=isUserRegistered,roompass=tournament.roomCode,scores=scores)
        else:
            return render_template('tournamentsdetails.html', error="Tournament not found",tournament=None)
    else:
        return render_template('tournamentsdetails.html', error="Tournament not found",tournament=None)


@app.route('/host/')
def host_tournament():
    if 'user' in session:
        autoAudit('User Accessed Host Tournament Page', session['userid'], 'User accessed host tournament page')
        username = session['user']
        user = users.query.filter_by(username=username).first()
        if user:
            return render_template('hosttourna.html', user=user)
        else:
            return redirect(url_for('auth'))
    else:
        return redirect(url_for('auth'))

@app.route('/edit/')
def edit_tournament():
    if 'user' in session:
        username = session['user']
        autoAudit('User Accessed Edit Tournament Page', session['userid'], 'User accessed edit tournament page')
        user = users.query.filter_by(username=username).first()
        if user:
            tourId = request.args.get('tournamentid', None)
            tournament = None
            if tourId != None:
                tournament = tournamentInfo.query.filter_by(tournamentid=tourId).first()
                if tournament and tournament.host == user.userid:
                    
                    return render_template('edittournament.html', user=user, tournament=tournament)
                else:
                    return redirect(url_for('host_tournament'))
            else:
                return redirect(url_for('host_tournament'))
        else:
            return redirect(url_for('auth'))
    else:
        return redirect(url_for('auth'))

@app.route('/profile/')
def user_profile():
    if 'user' in session:
        username = session['user']
        autoAudit('User Accessed Profile Page', session['userid'], 'User accessed profile page')
        user = users.query.filter_by(username=username).first()
        if user:
            checkHostedTournaments = tournamentInfo.query.filter_by(host=user.userid).all()
            registerdTournaments = tournamentRegistration.query.filter_by(userId=user.userid).all()
            if checkHostedTournaments:
                hostedTournaments = checkHostedTournaments
            else:
                hostedTournaments = None

            registered = []
            if registerdTournaments:
                for tournament in registerdTournaments:
                    tournamentDetails = tournamentInfo.query.filter_by(tournamentid=tournament.tournamentid).first()
                    if tournamentDetails:
                        if tournamentDetails.status == 'deleted':
                            continue
                        
                        tournamentDetails.createdAt = tournament.createdAt
                        tournamentDetails.teamName = tournament.teamName
                        tournamentDetails.memberCount = tournament.teamCount
                        tournamentDetails.teamMembers = [tournament.teamMember1, tournament.teamMember2, tournament.teamMember3, tournament.teamMember4, tournament.teamMember5]

                        registered.append(tournamentDetails)
            
            return render_template('cuserprofile.html', user=user, hostedTournament=hostedTournaments, registeredTournaments=registered)
        else:
            return redirect(url_for('auth'))
    else:
        return redirect(url_for('auth'))

@app.route('/withdrawal/<path>/')
def WithdrawalManagement(path):
    if 'admin' not in session :
        return redirect(url_for('adminlogin'))

    if path == 'request':
        autoAudit('User Accessed Withdrawal Requests', session.get('userid', 'Guest'), 'User accessed withdrawal requests')
        if 'admin' in session:
            withdrawal_requests = transactions.query.filter_by(type='withdrawal',status='pending').all()
            return render_template('withdrawalrequest.html', withdrawal_requests=withdrawal_requests)
    
    elif path == 'info':
        autoAudit('User Accessed Withdrawal Info', session.get('userid', 'Guest'), 'User accessed withdrawal info')
        transactionid = request.args.get('transactionid')
        transaction = transactions.query.filter_by(transactionId=transactionid).first()
        if transaction:
            user = users.query.filter_by(userid=transaction.userId).first()
            details = json.loads(str(transaction.description).replace("'", '"'))
            if user:
                return render_template('withdrawalinfo.html', transaction=transaction, detail=details, user=user)
            else:
                return redirect(url_for('WithdrawalManagement', path='request', toast='User not found!'))
    

@app.route('/wallet/')
def user_wallet():
    if 'user' in session:
        username = session['user']
        user = users.query.filter_by(username=username).first()
        if user:
            wallet = userWallet.query.filter_by(userId=user.userid).first()
            if not wallet:
                wallet = userWallet(userId=user.userid)
                database.session.add(wallet)
                database.session.commit()
            transactions_list = transactions.query.filter_by(userId=user.userid).all()
            for transaction in transactions_list:
                expireTransaction = False 
                if transaction.status == 'pending' and transaction.type != 'withdrawal':
                    created_at = datetime.strptime(transaction.createdAt, "%Y-%m-%d %H:%M:%S")
                    if (datetime.now() - created_at).total_seconds() > 900:  # 15 minutes
                        expireTransaction = True
                    checkOrder = paymentClient.order.fetch(transaction.transactionId)
                    if checkOrder and checkOrder['status'] == 'paid':
                        transaction.status = 'Success'
                        wallet.balance += transaction.amount
                        database.session.commit()
                    elif expireTransaction or checkOrder['status'] == 'failed':
                        transaction.status = 'Failed'
                        database.session.commit()
            return render_template('wallet.html', user=user, wallet=wallet, transactions=transactions_list,toast=request.args.get('toast', ''))
        else:
            return redirect(url_for('auth'))
    else:
        return redirect(url_for('auth'))



if __name__ == '__main__':
    with app.app_context():
        database.create_all()
    app.run()
