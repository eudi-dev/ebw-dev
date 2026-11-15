# Every organisation has its own business wallet

A business wallet holds the credentials of a legal person. Several people act for that person. The proposal COM(2025) 838 asks for several users in one wallet (Article 5(1)(j)) and role mappings (Article 6(2)(b)). It defines no format. eudi-dev is a test wallet for natural persons.

## Decision

The business wallet is a product of its own in this repository. People create organisations. Each organisation has its own business wallet with its own credentials, keys and activity log, and its own members and roles. Members prove who they are with their personal PID. On a public instance every visitor can create a test organisation.

eudi-dev gets no members, roles or organisations. Delegate SD-JWT is a feature of eudi-dev. It works with personal wallets and with business wallets and stays behind the experimental switch.

## Consequences

The organisation service, the identity check and the pages for organisations, members and roles are new code in this repository. The AI agent demo becomes one example inside an organisation. The eudi-dev branch `feat/delegate-sd-jwt` holds code for users and roles. It is reference material until the organisation service exists.
