from django.core.mail import send_mail
from django.shortcuts import render
from django.http import HttpResponse
import requests
import os
from dotenv import load_dotenv
from .forms import ContactForm

# Cargar las variables de entorno del archivo .env
load_dotenv()


def home(request):
    print(os.environ.get("TURNSTILE_SECRET"))
    if request.method == "POST":
        # Crear el formulario con los datos enviados por POST
        form = ContactForm(request.POST)
        turnstile_secret = os.environ.get("TURNSTILE_SECRET")

        if not turnstile_secret:
            print("Turnstile secret key is missing.")
            return render(request, 'main/home.html', {
                'form': form,
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

            # Validar respuesta de Turnstile
            turnstile_response = request.POST.get('cf-turnstile-response')
            if not turnstile_response:
                print("Turnstile response is missing.")
                return render(request, 'main/home.html', {
                    'form': form,
                    'error': "Turnstile response missing. Please try again."
                })

            # Enviar la solicitud a Turnstile
            url = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
            data = {
                "secret": turnstile_secret,
                "response": turnstile_response
            }
            response = requests.post(url, data=data)
            result = response.json()
            print("Turnstile API Response:", result)

            if result.get("success"):
                # Turnstile validó correctamente
                send_email(request, name, email, subject, body)
                return render(request, 'main/home.html', {
                    'form': ContactForm(),  # Limpiar el formulario tras éxito
                    'success': "Form submitted successfully!"
                })
            else:
                # Fallo en Turnstile
                error_message = "Failed Turnstile verification."
                error_codes = result.get("error-codes", [])
                if error_codes:
                    error_message += f" Errors: {', '.join(error_codes)}"
                return render(request, 'main/home.html', {
                    'form': form,
                    'error': error_message
                })

        else:
            # Errores en el formulario
            print("Form Errors:", form.errors)
            return render(request, 'main/home.html', {
                'form': form,
                'error': "Please correct the errors in the form."
            })

    else:
        # GET request
        form = ContactForm()

    return render(request, 'main/home.html', {'form': form})


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
