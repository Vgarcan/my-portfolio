from django.core.mail import send_mail
from django.shortcuts import render
import os
from .forms import ContactForm
from django.conf import settings

from django.conf import settings
# Asegúrate de que esta función esté en un archivo utils.py o similar
from _core.utils import turnstile_validation


def home(request):
    """
    View function for home page
    """
    # Instancing the variables for TURNSTILE
    turnstile_sitekey = settings.TURNSTILE_SITEKEY
    turnstile_secret = settings.TURNSTILE_SECRET
    turnstile_verify_url = settings.TURNSTILE_VERIFY_URL
    turnstile_js_api_url = settings.TURNSTILE_JS_API_URL

    # Imprimir los detalles de Turnstile para depuración
    print(f"""
          Turnstile Sitekey: {turnstile_sitekey}
          Turnstile Secret: {turnstile_secret}
          Turnstile Verify URL: {turnstile_verify_url}
          """)

    if request.method == "POST":
        # Crear el formulario con los datos enviados por POST
        form = ContactForm(request.POST)

        if not turnstile_secret:
            print("Turnstile secret key is missing.")
            return render(request, 'main/home.html', {
                'form': form,
                'sitekeyTurnstile': turnstile_sitekey,
                'error': "Server configuration error: missing Turnstile secret key."
            })

        # Validar el formulario
        if form.is_valid():
            print(">>> FORM IS VALID")
            name = form.cleaned_data['name']
            email = form.cleaned_data['email']
            subject = form.cleaned_data['subject']
            body = form.cleaned_data['body']

            print(f"""
                Name: {name}
                Email: {email}
                Subject: {subject}
                Body: {body}
            """)

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
            print("Form Errors:", form.errors)
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
    except Exception as e:
        print(f"Error al enviar el correo: {e}")
        return render(request, 'main/home.html', {
            'form': ContactForm(),
            'error': f"An error occurred while sending the email: {str(e)}"
        })
