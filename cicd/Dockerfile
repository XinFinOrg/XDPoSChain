# Support setting various labels on the final image
ARG GIT_COMMIT=""

FROM golang:1.25-alpine AS builder

RUN apk add make build-base linux-headers

WORKDIR /builder

COPY . .

# A BuildKit cache mount: `COPY . .` invalidates this layer on every commit, so
# the Go build cache is the only thing that survives across builds.
RUN --mount=type=cache,target=/root/.cache/go-build make puppeth && make

# The runtime image
FROM alpine:3

ENV GODEBUG=randseednop=0

WORKDIR /work

RUN apk add --no-cache bash curl

COPY --from=builder /builder/build/bin/puppeth /usr/bin
COPY --from=builder /builder/build/bin/XDC /usr/bin/XDC

# # Copy over files
ADD cicd/local /work/local
ADD cicd/subnet /work/subnet
ADD cicd/entry.sh /work/entry.sh
ADD cicd/puppeth.sh /work/puppeth.sh

# Create an empty pwd file
RUN touch /work/.pwd

# rpc
EXPOSE 8545
# ws
EXPOSE 8555
# port
EXPOSE 30303

ENTRYPOINT ["bash","/work/entry.sh"]

# Add some metadata labels to help programmatic image consumption
ARG GIT_COMMIT=""
ENV GIT_COMMIT="$GIT_COMMIT"
LABEL git_commit="$GIT_COMMIT"
