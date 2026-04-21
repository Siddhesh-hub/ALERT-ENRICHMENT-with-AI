# Use the AWS Lambda Python runtime as base image
FROM public.ecr.aws/lambda/python:3.9

# Copy requirements.txt and install dependencies
COPY requirements.txt ${LAMBDA_TASK_ROOT}
RUN pip install -r requirements.txt --target "${LAMBDA_TASK_ROOT}"

# Copy the Lambda function code
COPY lambda_function.py ${LAMBDA_TASK_ROOT}

# Set the CMD to the Lambda handler
CMD [ "lambda_function.lambda_handler" ]