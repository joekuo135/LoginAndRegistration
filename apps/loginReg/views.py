from django.shortcuts import render, redirect, HttpResponse
from .models import User
from django.contrib import messages
import bcrypt

# Create your views here.

def index(request):
    return render(request, 'loginReg/index.html')


def login(request):
    if request.method == 'POST':
        try:
            get_email = User.objects.get(email = request.POST['email'])
            if bcrypt.checkpw(request.POST['password'].encode(), get_email.password.encode()):
                request.session['user_id'] = get_email.id

                current_user = User.objects.get(id=request.session['user_id'])              
                return redirect('/success')
        except:
            messages.error(request, 'Your Login information does not match our database. Please try again.')
        
    return redirect('/')

def register(request):
    if request.method == 'POST':
        errors = User.objects.the_validator(request.POST)
        
        if len(errors):
            for error in errors:
                messages.error(request, error)
            return redirect('/register')
        else:
            try:
                check_email = User.objects.get(email = request.POST['email'])
                messages.error(request, 'This email already exists.')
                return redirect('/')
            except:
                hash_pw = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt())

                user = User(first_name=request.POST['first_name'], last_name=request.POST['last_name'],email=request.POST['email'],password=hash_pw,birthday=request.POST['birthday'])       
                user.save()
                messages.success(request, 'You have successfully registered')
    return redirect('/')


def success(request):
    if 'user_id' not in request.session:
        return redirect('/')
    user = User.objects.get(id=request.session['user_id'])
    context = {
        'current_user_id': request.session['user_id'],
    }
    return render(request, 'loginReg/success.html', context)



