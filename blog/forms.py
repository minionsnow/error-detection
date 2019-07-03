from django import forms

class ContactForm(forms.Form):
    host=forms.CharField(label='',widget=forms.TextInput(attrs={"placeholder":"Host","class":"form-control"}))
    console=forms.CharField(label='',widget=forms.TextInput(attrs={"placeholder":"Console","class":"form-control"}))
    username=forms.CharField(label='',widget=forms.TextInput(attrs={"placeholder":"Username","class":"form-control"}))
    password=forms.CharField(label='',widget=forms.TextInput(attrs={"placeholder":"Password","class":"form-control"}))
