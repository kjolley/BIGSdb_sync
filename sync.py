# Client software for synchronising sequence definition and isolate databases
# with a remote BIGSdb installation via the API
# Written by Keith Jolley
# Copyright (c) 2025, University of Oxford
# E-mail: keith.jolley@biology.ox.ac.uk
#
# BIGSdb_sync is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# BIGSdb_sync is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

import re
import sys
from typing import List, Optional

import config
from api_client import get_route
from utils import (
    extract_last_value_from_url,
    extract_locus_names_from_urls,
)
from errors import DBError, APIError, ConfigError


def get_local_db_type():
    try:
        db_type = config.script.datastore.run_query(
            "SELECT value FROM db_attributes WHERE field=?", "type"
        )
    except ValueError as e:
        raise DBError("Could not determine local database type.") from e
    if db_type not in ("seqdef", "isolates"):
        raise ConfigError("Invalid db_type for local database.")
    return db_type


def get_remote_db_type():
    try:
        response = get_route(config.args.api_db_url, config.session_provider)
        if "isolates" in response:
            return "isolates"
        elif "sequences" in response:
            return "seqdef"
        raise DBError("Cannot determine remote database type.")
    except Exception as e:
        raise APIError(f"Failed to fetch top level database route: {e}") from e


def get_local_users():
    try:
        return config.script.datastore.run_query(
            "SELECT * FROM users ORDER BY id",
            None,
            {"fetch": "all_arrayref", "slice": {}},
        )
    except Exception as e:
        raise DBError(f"Failed to fetch local users: {e}") from e


def add_user(url: str):
    try:
        user = get_route(url, config.session_provider)
    except Exception as e:
        raise APIError(f"Failed to fetch user from {url}: {e}") from e
    db = config.script.db
    try:
        with db.cursor() as cursor:
            cursor.execute(
                "INSERT INTO users (id,user_name,surname,first_name,affiliation,status,"
                "date_entered,datestamp,curator) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                [
                    user.get("id"),
                    f"user-{user.get('id')}",
                    user.get("surname"),
                    user.get("first_name"),
                    user.get("affiliation"),
                    "user",
                    "now",
                    "now",
                    0,
                ],
            )
        db.commit()
        config.script.logger.info(
            f"User {user.get('id')}: {user.get('first_name')} {user.get('surname')} added."
        )
    except Exception as e:
        db.rollback()
        raise DBError(f"INSERT failed adding user {url}: {e}") from e


def get_remote_locus_list(schemes: Optional[List[int]], loci: Optional[List[str]]):
    locus_urls = []
    if schemes:
        for scheme_id in schemes:
            scheme_loci = get_route(
                f"{config.args.api_db_url}/schemes/{scheme_id}/loci",
                config.session_provider,
            )
            if scheme_loci.get("loci"):
                locus_urls.extend(scheme_loci["loci"])
    if loci:
        for locus in loci:
            if re.search(r"[^\w_\-']", locus):
                config.script.logger.error(f"Invalid locus name in list: {locus}.")
            else:
                locus_urls.append(f"{config.args.api_db_url}/loci/{locus}")
    if schemes is None and loci is None:
        loci_resp = get_route(
            f"{config.args.api_db_url}/loci?return_all=1", config.session_provider
        )
        if loci_resp.get("loci"):
            locus_urls.extend(loci_resp["loci"])
    locus_urls = list(dict.fromkeys(locus_urls))
    return locus_urls


def get_local_locus_list(
    schemes: Optional[List[int]] = None, loci: Optional[List[str]] = None
):
    locus_list = []
    try:
        if schemes:
            for scheme_id in schemes:
                scheme_loci = config.script.datastore.get_scheme_loci(scheme_id)
                if scheme_loci:
                    locus_list.extend(scheme_loci)
        if loci:
            all_loci = config.script.datastore.get_loci()
            if all(locus in all_loci for locus in loci):
                locus_list.extend(loci)
            else:
                missing = [locus for locus in loci if locus not in all_loci]
                raise ConfigError(f"Following loci not defined locally: {missing}")
        locus_list = list(dict.fromkeys(locus_list))
        if schemes is None and loci is None:
            locus_list = config.script.datastore.get_loci()
        return locus_list
    except Exception as e:
        raise DBError(f"Failed to build local locus list: {e}") from e


def add_new_loci(loci: List[str]):
    db = config.script.db

    for locus in loci:
        url = f"{config.args.api_db_url}/loci/{locus}"
        locus_info = get_route(url, config.session_provider)
        possible_fields = [
            "id",
            "data_type",
            "allele_id_format",
            "coding_sequence",
            "formatted_name",
            "common_name",
            "formatted_common_name",
            "locus_type",
            "allele_id_regex",
            "length",
            "length_varies",
            "min_length",
            "max_length",
            "complete_cds",
            "start_codons",
            "orf",
            "genome_position",
            "match_longest",
            "id_check_type_alleles",
            "id_check_threshold",
        ]
        fields = []
        placeholders = []
        values = []
        for field in possible_fields:
            if locus_info.get(field) is None:
                continue
            fields.append(field)
            values.append(locus_info.get(field))
            placeholders.append("%s")
        fields.extend(["curator", "date_entered", "datestamp"])
        placeholders.extend(["%s", "%s", "%s"])
        values.extend([0, "now", "now"])
        inserts = []
        qry = (
            "INSERT INTO loci ("
            + ",".join(fields)
            + ") VALUES ("
            + ",".join(placeholders)
            + ")"
        )
        inserts.append({"qry": qry, "values": values})

        if locus_info.get("aliases"):
            aliases = locus_info.get("aliases")
            for alias in aliases:
                inserts.append(
                    {
                        "qry": "INSERT INTO locus_aliases (locus,alias,curator,datestamp) VALUES (%s,%s,%s,%s)",
                        "values": [locus, alias, 0, "now"],
                    }
                )
        db_type = get_local_db_type()
        if db_type == "seqdef":
            # locus_descriptions
            if set(["full_name", "product", "description"]) & locus_info.keys():
                inserts.append(
                    {
                        "qry": "INSERT INTO locus_descriptions(locus,full_name,product,description,"
                        "datestamp,curator) VALUES (%s,%s,%s,%s,%s,%s)",
                        "values": [
                            locus,
                            locus_info.get("full_name"),
                            locus_info.get("product"),
                            locus_info.get("description"),
                            "now",
                            0,
                        ],
                    }
                )
            # extended attributes
            if locus_info.get("extended_attributes"):
                attributes = locus_info.get("extended_attributes")
                for attribute in attributes:
                    option_list = None
                    if attribute.get("allowed_values"):
                        option_list = "|".join(attribute.get("allowed_values"))
                    inserts.append(
                        {
                            "qry": "INSERT INTO locus_extended_attributes "
                            "(locus,field,value_format,length,value_regex,description,option_list,"
                            "required,field_order,main_display,datestamp,curator) VALUES "
                            "(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                            "values": [
                                locus,
                                attribute.get("field"),
                                attribute.get("value_format"),
                                attribute.get("length"),
                                attribute.get("value_regex"),
                                attribute.get("description"),
                                option_list,
                                attribute.get("required"),
                                attribute.get("field_order"),
                                True,
                                "now",
                                0,
                            ],
                        }
                    )
            # peptide_mutations (SAVs)
            if locus_info.get("SAVs"):
                savs = locus_info.get("SAVs")
                id_ = config.script.datastore.run_query(
                    "SELECT COALESCE(MAX(id),0) FROM peptide_mutations"
                )

                for sav in savs:
                    id_ += 1
                    variant_aa = ";".join(sav.get("variant_aa"))
                    wild_type_aa = ";".join(sav.get("wild_type_aa"))
                    inserts.append(
                        {
                            "qry": "INSERT INTO peptide_mutations (id,locus,wild_type_allele_id,"
                            "reported_position,locus_position,wild_type_aa,variant_aa,flanking_length,"
                            "curator,datestamp) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                            "values": [
                                id_,
                                locus,
                                None,
                                sav.get("reported_position"),
                                sav.get("locus_position"),
                                wild_type_aa,
                                variant_aa,
                                sav.get("flanking_length"),
                                0,
                                "now",
                            ],
                        }
                    )
            # dna_mutations (SNPs)
            if locus_info.get("SNPs"):
                snps = locus_info.get("SNPs")
                id_ = config.script.datastore.run_query(
                    "SELECT COALESCE(MAX(id),0) FROM dna_mutations"
                )

                for snp in snps:
                    id_ += 1
                    variant_nuc = ";".join(snp.get("variant_nuc"))
                    wild_type_nuc = ";".join(snp.get("wild_type_nuc"))
                    inserts.append(
                        {
                            "qry": "INSERT INTO dna_mutations (id,locus,wild_type_allele_id,"
                            "reported_position,locus_position,wild_type_nuc,variant_nuc,flanking_length,"
                            "curator,datestamp) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                            "values": [
                                id_,
                                locus,
                                None,
                                snp.get("reported_position"),
                                snp.get("locus_position"),
                                wild_type_nuc,
                                variant_nuc,
                                snp.get("flanking_length"),
                                0,
                                "now",
                            ],
                        }
                    )
        try:
            with db.cursor() as cursor:
                for insert in inserts:
                    cursor.execute(insert.get("qry"), insert.get("values", []))
            db.commit()

            config.script.logger.info(f"Locus {locus} added.")
        except Exception as e:
            db.rollback()
            if "already exists" in str(e):
                config.script.logger.warning(f"Locus {locus} already exists. Skipped.")
                continue
            raise DBError(f"INSERT failed adding locus {locus}: {e}") from e


def should_check_existing_alleles():
    if config.args.check_seqs or config.args.update_seqs:
        return True
    return False


def add_or_check_new_seqs(loci: List[str]):
    users = get_local_users()
    user_ids = {user["id"] for user in users}

    should_check_existing = should_check_existing_alleles()
    for locus in loci:
        if config.args.check_seqs or config.args.update_seqs:
            local_seqs = config.script.datastore.run_query(
                "SELECT * FROM sequences WHERE locus=%s ORDER BY allele_id",
                locus,
                {"fetch": "all_arrayref", "slice": {}},
            )
        else:
            local_seqs = config.script.datastore.run_query(
                "SELECT allele_id FROM sequences WHERE locus=%s ORDER BY allele_id",
                locus,
                {"fetch": "all_arrayref", "slice": {}},
            )
        local_allele_ids = {seq["allele_id"] for seq in local_seqs}

        url = f"{config.args.api_db_url}/loci/{locus}/alleles?include_records=1"
        if config.args.reldate is not None:
            url += f"&updated_reldate={config.args.reldate}"
        extended_att = config.script.datastore.run_query(
            "SELECT * FROM locus_extended_attributes WHERE locus=?",
            locus,
            {"fetch": "all_arrayref", "slice": {}},
        )
        savs = config.script.datastore.run_query(
            "SELECT * FROM peptide_mutations WHERE locus=?",
            locus,
            {"fetch": "all_arrayref", "slice": {}},
        )
        snps = config.script.datastore.run_query(
            "SELECT * FROM dna_mutations WHERE locus=?",
            locus,
            {"fetch": "all_arrayref", "slice": {}},
        )

        while True:
            remote_seqs = get_route(url, config.session_provider)
            if (
                not should_check_existing
                and config.args.reldate is None
                and len(local_allele_ids) >= remote_seqs.get("records", 0)
            ):
                break
            if remote_seqs.get("alleles"):
                for seq in remote_seqs.get("alleles"):
                    if seq.get("allele_id") in local_allele_ids:
                        if should_check_existing:
                            check_seq(
                                locus=locus,
                                seq=seq,
                                user_ids=user_ids,
                                extended_att=extended_att,
                                savs=savs,
                                snps=snps,
                            )
                    else:
                        add_new_seq(
                            locus=locus,
                            seq=seq,
                            user_ids=user_ids,
                            extended_att=extended_att,
                            savs=savs,
                            snps=snps,
                        )
            else:
                config.script.logger.error(f"No alleles attribute for {locus}")
                break
            if remote_seqs.get("paging"):
                if remote_seqs.get("paging").get("next"):
                    url = remote_seqs.get("paging").get("next")
                    continue
                else:
                    break
            else:
                break


def check_record_users(record, user_ids):
    try:
        sender = int(extract_last_value_from_url(record.get("sender")))
    except Exception:
        raise APIError(f"Invalid sender value in remote record: {record}")
    if sender not in user_ids:
        add_user(record.get("sender"))
        user_ids.add(sender)
    try:
        curator = int(extract_last_value_from_url(record.get("curator")))
    except Exception:
        raise APIError(f"Invalid curator value in remote record: {record}")
    if curator not in user_ids:
        add_user(record.get("curator"))
        user_ids.add(curator)
    return sender, curator


def check_seq(locus, seq, user_ids, extended_att, savs, snps):
    db = config.script.db
    sender, curator = check_record_users(seq, user_ids)
    local_record = config.script.datastore.run_query(
        "SELECT * FROM sequences WHERE (locus,allele_id)=(?,?)",
        [locus, seq.get("allele_id")],
        {"fetch": "row_hashref"},
    )
    raise ConfigError("--check_seq not implemented yet.")
    print(local_record)


def add_new_seq(locus, seq, user_ids, extended_att, savs, snps):
    db = config.script.db
    sender, curator = check_record_users(seq, user_ids)

    inserts = []
    inserts.append(
        {
            "qry": "INSERT INTO sequences (locus,allele_id,sequence,status,comments,"
            "type_allele,sender,curator,date_entered,datestamp) VALUES "
            "(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            "values": [
                locus,
                seq.get("allele_id"),
                seq.get("sequence"),
                seq.get("status"),
                seq.get("comments"),
                seq.get("type_allele"),
                sender,
                curator,
                seq.get("date_entered"),
                seq.get("datestamp"),
            ],
        }
    )
    for att in extended_att:
        if seq.get(att.get("field")) is not None:
            field = att.get("field")
            inserts.append(
                {
                    "qry": "INSERT INTO sequence_extended_attributes "
                    "(locus,field,allele_id,value,datestamp,curator) VALUES "
                    "(%s,%s,%s,%s,%s,%s)",
                    "values": [
                        locus,
                        field,
                        seq.get("allele_id"),
                        seq.get(field),
                        seq.get("datestamp"),
                        curator,
                    ],
                }
            )
    if seq.get("SAVs"):
        for sav in seq.get("SAVs"):
            sav_ids = config.script.datastore.run_query(
                "SELECT id FROM peptide_mutations WHERE (locus,reported_position)=(%s,%s)",
                [locus, sav.get("position")],
                {"fetch": "col_arrayref"},
            )
            for sav_id in sav_ids:
                inserts.append(
                    {
                        "qry": "INSERT INTO sequences_peptide_mutations "
                        "(locus,allele_id,mutation_id,amino_acid,is_wild_type,"
                        "is_mutation,curator,datestamp) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                        "values": [
                            locus,
                            seq.get("allele_id"),
                            sav_id,
                            sav.get("amino_acid"),
                            True if sav.get("wild_type") else False,
                            True if sav.get("mutation") else False,
                            0,
                            "now",
                        ],
                    }
                )
    if seq.get("SNPs"):
        for snp in seq.get("SNPs"):
            snp_ids = config.script.datastore.run_query(
                "SELECT id FROM dna_mutations WHERE (locus,reported_position)=(%s,%s)",
                [locus, snp.get("position")],
                {"fetch": "col_arrayref"},
            )
            for snp_id in snp_ids:
                inserts.append(
                    {
                        "qry": "INSERT INTO sequences_dna_mutations "
                        "(locus,allele_id,mutation_id,nucleotide,is_wild_type,"
                        "is_mutation,curator,datestamp) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                        "values": [
                            locus,
                            seq.get("allele_id"),
                            snp_id,
                            snp.get("nucleotide"),
                            True if snp.get("wild_type") else False,
                            True if snp.get("mutation") else False,
                            0,
                            "now",
                        ],
                    }
                )
    if seq.get("publications"):
        for ref in seq.get("publications"):
            inserts.append(
                {
                    "qry": "INSERT INTO sequence_refs "
                    "(locus,allele_id,pubmed_id,curator,datestamp) VALUES "
                    "(%s,%s,%s,%s,%s)",
                    "values": [
                        locus,
                        seq.get("allele_id"),
                        ref.get("pubmed_id"),
                        0,
                        "now",
                    ],
                }
            )
    if seq.get("accessions"):
        for accession in seq.get("accessions"):
            inserts.append(
                {
                    "qry": "INSERT INTO accession "
                    "(locus,allele_id,databank,databank_id,curator,datestamp) VALUES "
                    "(%s,%s,%s,%s,%s,%s)",
                    "values": [
                        locus,
                        seq.get("allele_id"),
                        accession.get("databank"),
                        accession.get("accession"),
                        0,
                        "now",
                    ],
                }
            )
    try:
        with db.cursor() as cursor:
            for insert in inserts:
                cursor.execute(insert.get("qry"), insert.get("values"))
        db.commit()
        config.script.logger.info(f"Locus {locus}-{seq.get('allele_id')} added.")
    except Exception as e:
        db.rollback()
        raise DBError(
            f"INSERT failed adding sequence {locus}-{seq.get('allele_id')}: {e}"
        ) from e


def update_seqdef():
    selected_schemes = None
    selected_loci = None
    if config.args.schemes:
        try:
            selected_schemes = sorted(
                {int(scheme_id.strip()) for scheme_id in config.args.schemes.split(",")}
            )
        except ValueError:
            raise ConfigError("Invalid non-integer value found in --schemes argument.")
    if config.args.loci:
        selected_loci = sorted({locus.strip() for locus in config.args.loci.split(",")})

    remote_locus_urls = get_remote_locus_list(
        schemes=selected_schemes, loci=selected_loci
    )
    remote_loci = extract_locus_names_from_urls(remote_locus_urls)

    local_loci = get_local_locus_list()
    remote_count = len(remote_loci)
    local_count = len(local_loci)
    if remote_count != local_count:
        filtered = " (filtered)" if selected_loci or selected_schemes else ""
        config.script.logger.debug(
            f"Remote loci{filtered}: {remote_count}; Local loci: {local_count}"
        )
        not_in_local = [x for x in remote_loci if x not in local_loci]
        if len(not_in_local):
            if len(not_in_local) > 20:
                if config.args.log_level != "DEBUG":
                    config.script.logger.info(
                        f"There are {len(not_in_local)} loci not defined in local. "
                        "Run with --log_level DEBUG to list these."
                    )
                config.script.logger.debug(f"Not defined in local: {not_in_local}")
            else:
                config.script.logger.info(f"Not defined in local: {not_in_local}")
            if config.args.add_new_loci:
                add_new_loci(not_in_local)
            else:
                config.script.logger.info(
                    "Run with --add_new_loci to define these locally."
                )

    if config.args.add_new_seqs or config.args.check_seqs or config.args.update_seqs:
        local_loci = get_local_locus_list(schemes=selected_schemes, loci=selected_loci)
        if config.args.reldate is not None:
            updated_remote_locus_urls = get_route(
                f"{config.args.api_db_url}/loci?return_all=1&alleles_updated_reldate={config.args.reldate}",
                config.session_provider,
            )
            remote_loci = extract_locus_names_from_urls(
                updated_remote_locus_urls.get("loci", [])
            )
            local_set = set(local_loci)
            local_loci = [locus for locus in remote_loci if locus in local_set]

        add_or_check_new_seqs(local_loci)
