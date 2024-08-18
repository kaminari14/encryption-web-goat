CREATE TABLE public.users (
    email character varying(80) NOT NULL,
    password character varying(20)
);


COPY public.users (email, password) FROM stdin;
admin@admin.com	password
admin@test.com	123456
\.


GRANT ALL ON DATABASE test_db_73ccdee6 TO test_user_73ccdee6;
ALTER TABLE public.users OWNER TO test_user_73ccdee6;
