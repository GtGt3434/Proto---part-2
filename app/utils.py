import requests
import os

from .models import VolunteerOpportunity
from dotenv import load_dotenv
from flask import current_app
import PyPDF2
import sys


def fetch_unsplash_image(query):
    access_key = os.getenv('UNSPLASH_ACCESS_KEY')
    url = f"https://api.unsplash.com/photos/random?query={query}&client_id={access_key}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        return data['urls']['regular']
    else:
        return '/static/images/Charity Logo.jpg'  # Path to your default image

def match_opportunities(skills_interests):
    keywords = {keyword.strip().lower() for keyword in skills_interests.split(',')}
    matched_opportunities = []

    opportunities = VolunteerOpportunity.query.all()
    for opportunity in opportunities:
        if any(keyword in opportunity.skills_keywords.lower() for keyword in keywords):
            matched_opportunities.append(opportunity)

    return matched_opportunities


# Load the .env file
dotenv_path = os.path.join(os.path.dirname(__file__), '../instance/.env')
load_dotenv(dotenv_path)


def extract_text_from_file(file):
    """Extract text content from the uploaded file."""
    if file.filename.lower().endswith('.pdf'):
        reader = PyPDF2.PdfReader(file)
        text = ''
        for page in reader.pages:
            text += page.extract_text()
        return text
    return ''


def evaluate_assistance_request(full_name, age, gender, contact, assistance_type, description, income, expenses, assistance_amount, extracted_texts):
    """Evaluate the credibility of an assistance request using GPT-4 and generate a summary if truthful."""

    # Existing API key and headers setup
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        current_app.logger.error("OpenAI API key is not set.")
        return "Pending", "Error: API key not set"

    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json',
    }

    # Existing prompt creation and data setup
    prompt = (
        f"Evaluate the credibility of the following assistance request based on the provided information:\n"
        f"Full Name: {full_name}\n"
        f"Age: {age}\n"
        f"Gender: {gender}\n"
        f"Contact Number: {contact}\n"
        f"Type of Assistance: {assistance_type}\n"
        f"Description: {description}\n"
        f"Monthly Income: {income}\n"
        f"Monthly Expenses: {expenses}\n"
        f"Assistance Amount Required: {assistance_amount}\n"
        f"Supporting Documents Text: {extracted_texts}\n"
        "Provide a clear verdict on whether this request is likely truthful or likely untruthful. "
        "If you are confident in your evaluation, please use the exact phrases 'Likely Truthful' or 'Likely Untruthful' in your response. Make sure to elaborate on your reasoning."
    )

    # Log the prompt being sent
    current_app.logger.info(f"OpenAI API Prompt: {prompt}")

    data = {
        'model': 'gpt-4',
        'messages': [
            {'role': 'system', 'content': 'You are an AI model that evaluates the credibility of assistance requests. Your task is to determine if the request is likely truthful or not, based on the information provided.'},
            {'role': 'user', 'content': prompt}
        ],
        'max_tokens': 150
    }

    try:
        response = requests.post('https://api.openai.com/v1/chat/completions', headers=headers, json=data, timeout=60)
        response.raise_for_status()
        response_json = response.json()

        if 'choices' in response_json and len(response_json['choices']) > 0:
            evaluation_result = response_json['choices'][0]['message']['content']
            current_app.logger.info(f"Evaluation result: {evaluation_result}")
            
            # Determine the evaluation status
            if "likely truthful" in evaluation_result.lower():
                status = 'Likely Truthful'

                # Generate a summary if the request is likely truthful
                summary_prompt = (
                    f"Please summarize the assistance request using the following information:\n"
                    f"Full Name: {full_name}\n"
                    f"Age: {age}\n"
                    f"Gender: {gender}\n"
                    f"Type of Assistance: {assistance_type}\n"
                    f"Description: {description}\n"
                    f"Monthly Income: {income}\n"
                    f"Monthly Expenses: {expenses}\n"
                    f"Assistance Amount Required: {assistance_amount}\n"
                    "Since the request has been evaluated as likely truthful, provide a concise summary highlighting the key aspects of the aid seeker's situation."
                )

                summary_data = {
                    'model': 'gpt-4',
                    'messages': [
                        {'role': 'system', 'content': 'You are an AI model that generates summaries of assistance requests to aid in donor understanding.'},
                        {'role': 'user', 'content': summary_prompt}
                    ],
                    'max_tokens': 100
                }

                summary_response = requests.post('https://api.openai.com/v1/chat/completions', headers=headers, json=summary_data, timeout=60)
                summary_response.raise_for_status()
                summary_json = summary_response.json()

                if 'choices' in summary_json and len(summary_json['choices']) > 0:
                    summary = summary_json['choices'][0]['message']['content']
                    current_app.logger.info(f"Generated summary: {summary}")
                else:
                    summary = "No summary available."

            elif ("likely untruthful" in evaluation_result.lower() or 
                  "not truthful" in evaluation_result.lower() or 
                  "highly doubtful" in evaluation_result.lower() or
                  "not credible" in evaluation_result.lower()):
                status = 'Likely Untruthful'
                summary = None
            else:
                status = 'Pending'
                summary = None

            return status, evaluation_result, summary

        else:
            current_app.logger.error(f"Unexpected response format: {response_json}")
            return "Pending", "Error: Unexpected response format", None

    except requests.exceptions.RequestException as e:
        current_app.logger.error(f"Error contacting OpenAI API: {e}")
        return "Pending", "Error evaluating request", None
    except Exception as e:
        current_app.logger.error(f"Unexpected error: {e}")
        return "Pending", "Error evaluating request", None



def allowed_file(filename):
    """Check if a file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']