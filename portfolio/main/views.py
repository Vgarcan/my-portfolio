from django.core.mail import send_mail
from django.shortcuts import render
import requests
import os
from dotenv import load_dotenv
from .forms import ContactForm

# Cargar las variables de entorno del archivo .env
load_dotenv()

# Vista principal para mostrar y procesar el formulario


def home(request):
    if request.method == "POST":
        form = ContactForm(request.POST)

        # Validar formulario
        if form.is_valid():
            print(">>> FORM IS VALID")
            name = form.cleaned_data['name']
            email = form.cleaned_data['email']
            subject = form.cleaned_data['subject']
            body = form.cleaned_data['body']
            recaptcha_response = request.POST.get("g-recaptcha-response")

            print(f"""
                    Name: {name}
                    Email: {email}
                    Subject: {subject}
                    Body: {body}
                    ReCaptcha response: {recaptcha_response}
                    """)

            # Validar reCAPTCHA
            recaptcha_secret = os.getenv("RECAPTCHA_SECRET_KEY")
            recaptcha_url = "https://www.google.com/recaptcha/api/siteverify"
            recaptcha_data = {
                "secret": recaptcha_secret,
                "response": recaptcha_response
            }

            try:
                recaptcha_validation = requests.post(
                    recaptcha_url, data=recaptcha_data).json()
                print("Resultado de la validación reCAPTCHA:",
                      recaptcha_validation)

                if not recaptcha_validation.get("success"):
                    print("Errores de reCAPTCHA:",
                          recaptcha_validation.get("error-codes"))
                    print("Datos enviados a la API de reCAPTCHA:", recaptcha_data)
                    print("Respuesta completa de la API:", recaptcha_validation)

                    return render(request, 'main/home.html', {
                        'form': form,
                        'error': "Invalid reCAPTCHA. Please try again."
                    })

            except requests.RequestException as e:
                print(f"Error en la conexión con reCAPTCHA API: {e}")
                return render(request, 'main/home.html', {
                    'form': form,
                    'error': "Could not validate reCAPTCHA. Please try again later."
                })

            # Llamar a la función para enviar el correo
            return send_email(request, name, email, subject, body)

        else:
            print("Errores del formulario:", form.errors)
            return render(request, 'main/home.html', {
                'form': form,
                'error': "Please correct the errors in the form."
            })

    else:
        form = ContactForm()

    return render(
        request,
        'main/home.html',
        {
            'form': form,
        }
    )


def send_email(request, name, email, subject, body):
    # Construir el mensaje
    message = f"""
    You have a new contact form submission:

    Name: {name}
    Email: {email}

    Message:
    {body}
    """

    try:
        # Enviar el correo
        send_mail(
            subject=subject,
            message=message,
            from_email=os.environ.get("EMAIL_HOST_USER"),  # Tu correo SMTP
            recipient_list=[os.environ.get("EMAIL_HOST_USER")],  # Destinatario
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