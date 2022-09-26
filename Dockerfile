
FROM  golang:1.17-stretch AS builder
ADD . /src
WORKDIR /src
RUN go mod download
RUN cd cmd/chainbridge && go build -o /bridge .

# # final stage
FROM debian:stretch-slim
RUN apt-get -y update && apt-get -y upgrade && apt-get install ca-certificates -y

COPY --from=builder /bridge ./
RUN chmod +x ./bridge

ENTRYPOINT ["./bridge"]
