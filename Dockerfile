FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY dashboard ./dashboard
COPY data ./data
COPY models ./models
EXPOSE 7860
CMD ["streamlit", "run", "dashboard/app.py", "--server.port=7860", "--server.address=0.0.0.0"]