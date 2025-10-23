# BIGSdb_sync

Client software for synchronising sequence and scheme definitions 
with a remote BIGSdb installation via the API using OAuth authentication.

## Installation
It is recommended that you install this in a virtual environment, e.g.

```
git clone https://github.com/kjolley/BIGSdb_sync.git
cd BIGSdb_sync
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

You can de-activate the virtual environment with:

```
deactivate
```
## Accessing PubMLST and BIGSdb Pasteur APIs using authentication
The BIGSdb platform used for PubMLST and BIGSdb Pasteur uses OAuth 
authentication that enables you to delegate access using your account to a
script without having to share credentials.

First you need to register an account for the appropriate site (see 
[https://pubmlst.org/site-accounts](https://pubmlst.org/site-accounts)).

The addresses you need to do this are:

* PubMLST: [https://pubmlst.org/bigsdb](https://pubmlst.org/bigsdb)
* Pasteur: [https://bigsdb.pasteur.fr/cgi-bin/bigsdb/bigsdb.pl](https://bigsdb.pasteur.fr/cgi-bin/bigsdb/bigsdb.pl)

You then need to register this account with each database that you want to 
access. This can also be done at the above addresses.

Finally, you will need to obtain a client key and secret. For PubMLST, you can
now create a personal key at [https://pubmlst.org/bigsdb](https://pubmlst.org/bigsdb). 
For Pasteur, you currently need to request this via an E-mail to the following 
address (but an automated method to obtain personal keys will be available 
soon):

* Pasteur - [bigsdb@pasteur.fr](mailto:bigsdb@pasteur.fr)

## Local database setup
You need to be running BIGSdb locally with an empty database of the appropriate
type (sequence definition or isolates). In the following examples, the local 
database with be called `bigsdb_test_seqdef` and the configuration name will be
`test_seqdef`. See the [BIGSdb documentation](https://bigsdb.readthedocs.io/) for
details.

## Credential setup
Set up the credentials for the first time by running the script, providing the
URL for the top-level database API call that your account has access to, e.g. 
https://rest.pubmlst.org/db/pubmlst_neisseria_seqdef and the configuration name
of the local database that you will be synchronizing to.

```shell
./bigsdb_sync.py --key_name PubMLST \
                 --db test_seqdef \
                 --api_db_url https://rest.pubmlst.org/db/pubmlst_neisseria_seqdef
```
This will then prompt you to enter the client key and client secret that you 
have obtained. These will be stored as the provided key name in the 
token_directory (./.bigsdb_tokens by default but can be set using --token_dir 
argument).

You will then be prompted to login to a particular page on the BIGSdb site and
authorize delegation of your account access. This will provide you with a 
verification code that you will be prompted to enter by the script. Once done
an access token will be saved that will be used for all future access.

Session tokens will be obtained and renewed automatically by the script as 
required using your client key and access token.

## Setting up loci in local database
Use the `--add_new_loci argument` to set up new local loci based on loci found
in the remote database. You can filter this to a defined list using the 
`--add_new_loci argument` followed by a comma-separated list, e.g.

```shell
./bigsdb_sync.py --key_name PubMLST \
                 --db test_seqdef \
                 --api_db_url https://rest.pubmlst.org/db/pubmlst_neisseria_seqdef \
                 --add_new_loci \
                 --loci abcZ,adk,aroE
```

You can also set up all loci that are members of schemes in the remote 
database using the `--schemes` argument followed by a comma-separated list of
scheme ids, e.g.

```shell
./bigsdb_sync.py --key_name PubMLST \
                 --db test_seqdef \
                 --api_db_url https://rest.pubmlst.org/db/pubmlst_neisseria_seqdef \
                 --add_new_loci \
                 --schemes 1
```

## Adding new alleles
Use the `add_new_seqs` argument to retrieve and add new alleles to the local
database. You can use the `--loci` and `--schemes` filters to restrict the 
loci to update. You can also limit the update to only those modified in the 
last X days using the `--reldate` argument, e.g.

```shell
./bigsdb_sync.py --key_name PubMLST \
                 --db test_seqdef \
                 --api_db_url https://rest.pubmlst.org/db/pubmlst_neisseria_seqdef \
                 --add_new_seqs \
                 --reldate 7
```

Using `--reldate` is much more efficient because the API can provide a list of
loci for which alleles have been modified in the specified time, and then also 
only return those alleles, so it reduces the number of calls required. If you 
don't set `--reldate` then all alleles for a locus will be retrieved from the 
API and the script will filter these to add just the new ones.

Note that the `--schemes` filter here requires that the schemes used are
defined in the local database. This is different from the `--add_new_loci`
argument which necessarily uses schemes defined remotely (since the loci do
not exist locally yet and so cannot belong to a local scheme).