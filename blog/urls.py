from django.contrib import admin
from django.urls import path, include
from . import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.home,name='home'),
    path('output/', views.output ,name='script'),
    path('summary/', views.summary ,name='summary'),
    #path('logs/', views.logs ,name='logs'),
]
