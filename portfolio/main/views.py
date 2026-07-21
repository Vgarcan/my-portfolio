from django.core.mail import send_mail
from django.shortcuts import render
import logging
import os
from .forms import ContactForm
from django.conf import settings

from django.conf import settings
# Asegúrate de que esta función esté en un archivo utils.py o similar
from _core.utils import turnstile_validation


logger = logging.getLogger(__name__)


def home(request):
    """
    View function for home page
    """
    # Instancing the variables for TURNSTILE
    turnstile_sitekey = settings.TURNSTILE_SITEKEY
    turnstile_secret = settings.TURNSTILE_SECRET
    turnstile_verify_url = settings.TURNSTILE_VERIFY_URL

    if request.method == "POST":
        # Crear el formulario con los datos enviados por POST
        form = ContactForm(request.POST)

        if not turnstile_secret:
            logger.error("Turnstile secret key is missing.")
            return render(request, 'main/home.html', {
                'form': form,
                'sitekeyTurnstile': turnstile_sitekey,
                'error': "Server configuration error: missing Turnstile secret key."
            })

        # Validar el formulario
        if form.is_valid():
            name = form.cleaned_data['name']
            email = form.cleaned_data['email']
            subject = form.cleaned_data['subject']
            body = form.cleaned_data['body']

            # Validar Turnstile usando la función simplificada
            if turnstile_validation(request, turnstile_secret, turnstile_verify_url):
                # Turnstile validó correctamente
                send_email(request, name, email, subject, body)
                return render(request, 'main/home.html', {
                    'form': ContactForm(),  # Limpiar el formulario tras éxito
                    'sitekeyTurnstile': turnstile_sitekey,
                    'success': "Form submitted successfully!"
                })
            else:
                # Fallo en Turnstile
                return render(request, 'main/home.html', {
                    'form': form,
                    'sitekeyTurnstile': turnstile_sitekey,
                    'error': "Failed Turnstile verification. Please try again."
                })

        else:
            # Errores en el formulario
            return render(request, 'main/home.html', {
                'form': form,
                'sitekeyTurnstile': turnstile_sitekey,
                'error': "Please correct the errors in the form."
            })

    else:
        # GET request
        form = ContactForm()

    return render(request, 'main/home.html', {
        'form': form,
        'sitekeyTurnstile': turnstile_sitekey,
    })


def send_email(request, name, email, subject, body):
    # Build the Message
    message = f"""
    You have a new contact form submission:

    Name: {name}
    Email: {email}

    Message:
    {body}
    """

    try:
        # Send the email
        send_mail(
            subject=subject,
            message=message,
            # Your Address for the SMTP
            from_email=os.environ.get("EMAIL_HOST_USER"),
            # send to:
            recipient_list=[os.environ.get("EMAIL_HOST_USER")],
            fail_silently=False,
        )
        return render(request, 'main/home.html', {
            'form': ContactForm(),  # Renderiza un formulario vacío tras el éxito
            'success': "Message sent successfully!"
        })
    except Exception:
        logger.exception("Contact email could not be sent.")
        return render(request, 'main/home.html', {
            'form': ContactForm(),
            'error': "An error occurred while sending the email. Please try again later."
        })
