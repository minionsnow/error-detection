from django import forms

class ContactForm(forms.Form):
    host=forms.CharField()
    console=forms.CharField()
    username=forms.CharField()
    password=forms.CharField()
