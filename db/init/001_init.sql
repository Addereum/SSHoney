CREATE TABLE IF NOT EXISTS auth_attempts (
                                             id serial PRIMARY KEY,
                                             src_ip text,
                                             src_port integer,
                                             username text,
                                             password text,
                                             client_banner text,
                                             ts timestamptz DEFAULT now()
    );
