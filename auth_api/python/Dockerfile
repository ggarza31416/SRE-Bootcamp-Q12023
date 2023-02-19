FROM python:3-alpine

WORKDIR /src
COPY ./requirements.txt .
COPY ./ .

RUN pip install -r ./requirements.txt

ENV DB_USER=secret
ENV DB_PASSWORD=jOdznoyH6swQB9sTGdLUeeSrtejWkcw
ENV DB_HOST=sre-bootcamp-selection-challenge.cabf3yhjqvmq.us-east-1.rds.amazonaws.com
ENV DB_PORT=3306
ENV DB_DATABASE=bootcamp_tht
ENV JWT_KEY=my2w7wjd7yXF64FIADfJxNs1oupTGAuW

CMD [ "python", "./api.py"]

