# 1. Use a lightweight official Python image
FROM python:3.11-slim

# 2. Set the working directory inside the container
WORKDIR /app

# 3. Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 4. Copy the rest of your agent's code into the container
COPY . .

# 5. Expose port 5000 for Kibana webhooks
EXPOSE 5000

# 6. Command to run the application
CMD ["python", "agent_app.py"]
