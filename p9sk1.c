/*
 * p9sk1, p9sk2 - Plan 9 secret (private) key authentication.
 * p9sk2 is an incomplete, flawed variant of p9sk1.
 *
 * Client protocol (p9sk1 only):
 *   - write challenge[challen]
 *   - read tickreq[tickreqlen]
 *   - write ticket[ticketlen]
 *   - read authenticator[authentlen]
 *
 * Server protocol:
 *   - read challenge[challen] (p9sk1 only)
 *   - write tickreq[tickreqlen]
 *   - read ticket[ticketlen]
 *   - write authenticator[authentlen]
 */

#include "dat.h"

/* State structure representing the authentication state */
struct State {
	int vers;
	Key *key;
	Ticket t;
	Ticketreq tr;
	char cchal[CHALLEN];
	char tbuf[TICKETLEN + AUTHENTLEN];
	char authkey[DESKEYLEN];
	uchar *secret;
	int speakfor;
};

/* Phase definitions for client and server */
enum {
	/* Client phases */
	CHaveChal,
	CNeedTreq,
	CHaveTicket,
	CNeedAuth,

	/* Server phases */
	SNeedChal,
	SHaveTreq,
	SNeedTicket,
	SHaveAuth,

	Maxphase,
};

/* Phase names for debugging purposes */
static char *phasenames[Maxphase] = {
	[CHaveChal]    = "CHaveChal",
	[CNeedTreq]    = "CNeedTreq",
	[CHaveTicket]  = "CHaveTicket",
	[CNeedAuth]    = "CNeedAuth",

	[SNeedChal]    = "SNeedChal",
	[SHaveTreq]    = "SHaveTreq",
	[SNeedTicket]  = "SNeedTicket",
	[SHaveAuth]    = "SHaveAuth",
};

static int gettickets(State*, char*, char*);

/* Initializes the p9sk protocol (client or server) */
static int p9skinit(Proto *p, Fsstate *fss) {
	State *s;
	int iscli, ret;
	Key *k;
	Keyinfo ki;
	Attr *attr;

	if ((iscli = isclient(_strfindattr(fss->attr, "role"))) < 0)
		return failure(fss, nil);

	s = emalloc(sizeof(*s));
	fss = fss;
	fss->phasename = phasenames;
	fss->maxphase = Maxphase;

	/* Set version based on protocol type */
	if (p == &p9sk1) {
		s->vers = 1;
	} else if (p == &p9sk2) {
		s->vers = 2;
	} else {
		abort();
	}

	/* Initialize client or server based on role */
	if (iscli) {
		switch (s->vers) {
		case 1:
			fss->phase = CHaveChal;
			memrandom(s->cchal, CHALLEN);
			break;
		case 2:
			fss->phase = CNeedTreq;
			break;
		}
	} else {
		s->tr.type = AuthTreq;
		attr = setattr(_copyattr(fss->attr), "proto=p9sk1");
		mkkeyinfo(&ki, fss, attr);
		ki.user = nil;
		ret = findkey(&k, &ki, "user? dom?");
		_freeattr(attr);
		if (ret != RpcOk) {
			free(s);
			return ret;
		}
		safecpy(s->tr.authid, _strfindattr(k->attr, "user"), sizeof(s->tr.authid));
		safecpy(s->tr.authdom, _strfindattr(k->attr, "dom"), sizeof(s->tr.authdom));
		s->key = k;
		memrandom(s->tr.chal, sizeof(s->tr.chal));

		switch (s->vers) {
		case 1:
			fss->phase = SNeedChal;
			break;
		case 2:
			fss->phase = SHaveTreq;
			memmove(s->cchal, s->tr.chal, CHALLEN);
			break;
		}
	}

	fss->ps = s;
	return RpcOk;
}

/* Handles read requests for the p9sk protocol */
static int p9skread(Fsstate *fss, void *a, uint *n) {
	State *s = fss->ps;
	int m;

	switch (fss->phase) {
	default:
		return phaseerror(fss, "read");

	case CHaveChal:
		m = CHALLEN;
		if (*n < m)
			return toosmall(fss, m);
		*n = m;
		memmove(a, s->cchal, m);
		fss->phase = CNeedTreq;
		return RpcOk;

	case SHaveTreq:
		m = TICKREQLEN;
		if (*n < m)
			return toosmall(fss, m);
		*n = m;
		convTR2M(&s->tr, a);
		fss->phase = SNeedTicket;
		return RpcOk;

	case CHaveTicket:
		m = TICKETLEN + AUTHENTLEN;
		if (*n < m)
			return toosmall(fss, m);
		*n = m;
		memmove(a, s->tbuf, m);
		fss->phase = CNeedAuth;
		return RpcOk;

	case SHaveAuth:
		m = AUTHENTLEN;
		if (*n < m)
			return toosmall(fss, m);
		*n = m;
		memmove(a, s->tbuf + TICKETLEN, m);
		fss->ai.suid = s->t.suid;
		fss->ai.cuid = s->t.cuid;
		s->secret = emalloc(8);
		des56to64((uchar*)s->t.key, s->secret);
		fss->ai.secret = s->secret;
		fss->ai.nsecret = 8;
		fss->haveai = 1;
		fss->phase = Established;
		return RpcOk;
	}
}

/* Handles write requests for the p9sk protocol */
static int p9skwrite(Fsstate *fss, void *a, uint n) {
	State *s = fss->ps;
	Attr *attr;
	Keyinfo ki;
	int m;

	switch (fss->phase) {
	default:
		return phaseerror(fss, "write");

	case SNeedChal:
		m = CHALLEN;
		if (n < m)
			return toosmall(fss, m);
		memmove(s->cchal, a, m);
		fss->phase = SHaveTreq;
		return RpcOk;

	case CNeedTreq:
		m = TICKREQLEN;
		if (n < m)
			return toosmall(fss, m);

		convM2TR(a, &s->tr);
		if (s->vers == 2)
			memmove(s->cchal, s->tr.chal, CHALLEN);

		/* Retrieve key */
		attr = _delattr(_copyattr(fss->attr), "role");
		attr = setattr(attr, "proto=p9sk1");
		if (findkey(&s->key, &ki, "role=client dom=%q %s", s->tr.authdom, p9sk1.keyprompt) != RpcOk) {
			_freeattr(attr);
			return failure(fss, nil);
		}

		/* Get tickets */
		if (gettickets(s, trbuf, tbuf) < 0) {
			_freeattr(attr);
			return failure(fss, nil);
		}

		memmove(s->tbuf, tbuf + TICKETLEN, TICKETLEN);
		auth.num = AuthAc;
		convA2M(&auth, s->tbuf + TICKETLEN, s->t.key);
		fss->phase = CHaveTicket;
		return RpcOk;

	case SNeedTicket:
		m = TICKETLEN + AUTHENTLEN;
		if (n < m)
			return toosmall(fss, m);

		convM2T(a, &s->t, (char*)s->key->priv);
		convM2A((char*)a + TICKETLEN, &auth, s->t.key);
		auth.num = AuthAs;
		convA2M(&auth, s->tbuf + TICKETLEN, s->t.key);
		fss->phase = SHaveAuth;
		return RpcOk;

	case CNeedAuth:
		m = AUTHENTLEN;
		if (n < m)
			return toosmall(fss, m);
		convM2A(a, &auth, s->t.key);
		fss->ai.cuid = s->t.cuid;
		fss->ai.suid = s->t.suid;
		fss->haveai = 1;
		fss->phase = Established;
		return RpcOk;
	}
}

/* Closes the state and cleans up resources */
static void p9skclose(Fsstate *fss) {
	State *s = fss->ps;
	if (s->secret != nil) {
		free(s->secret);
	}
	if (s->key != nil) {
		closekey(s->key);
	}
	free(s);
}

Proto p9sk1 = {
	.name = "p9sk1",
	.init = p9skinit,
	.write = p9skwrite,
	.read = p9skread,
	.close = p9skclose,
	.addkey = p9skaddkey,
	.closekey = p9skclosekey,
	.keyprompt = "user? !password?"
};

Proto p9sk2 = {
	.name = "p9sk2",
	.init = p9skinit,
	.write = p9skwrite,
	.read = p9skread,
	.close = p9skclose,
};
