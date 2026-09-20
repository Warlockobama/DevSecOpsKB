FROM golang:1.24-alpine AS build
WORKDIR /src
COPY main.go .
RUN CGO_ENABLED=0 GO111MODULE=off go build -trimpath -o /out/jira-stub .

FROM scratch
COPY --from=build /out/jira-stub /jira-stub
ENTRYPOINT ["/jira-stub"]
