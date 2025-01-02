# Use the official AWS Lambda Python 3.9 base image
FROM public.ecr.aws/lambda/python:3.11

# Copy the function code into the container
COPY es_loader/ ${LAMBDA_TASK_ROOT}/

# Copy the layer contents into /opt
COPY es_loader_layer/ /opt/

# Set the CMD to your handler (could also be done as an argument)
CMD ["index.lambda_handler"]
