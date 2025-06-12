/* Copyright LiveTimeNet, Inc. 2025. All Rights Reserved. */

#include "langdict.h"

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>

#define LOCAL_DEBUG 0

struct langdict_item_s
{
    enum langdict_type_e langtype;
    unsigned int *dict_length;
    char **dict;

    uint64_t total_failed_lookups;
    uint64_t total_success_lookups;
    uint64_t total_found_words;

    time_t time_last_found; /* Walltime a successful lookup in the doctionary occured */
    time_t time_last_search; /* Walltime a lookup in the doctionary occured */
};

struct langdict_context_s
{
    struct langdict_item_s *dicts;
};

static const char *langdict_names[] = {
    "???",
    "eng",
    "spa",
    "ger",
    "ita",
    "fra"
};

const char *langdict_3letter_name(enum langdict_type_e langtype)
{
    return langdict_names[langtype];
}

/* Most used top english words, sorted alphabetically */
static unsigned int dict_eng_length = 200;
static char *dict_eng[] = {
    "a", "about", "above", "after", "again", "against", "all", "all", "am", "an", 
    "and", "any", "are", "aren't", "aren't", "as", "at", "be", "because", "been", 
    "before", "being", "below", "between", "both", "but", "by", "can't", "cannot", "could", 
    "couldn't", "did", "didn't", "do", "does", "doesn't", "doing", "don't", "down", "during", 
    "each", "few", "for", "from", "further", "good", "had", "hadn't", "has", "hasn't", 
    "have", "haven't", "having", "he", "he'd", "he'll", "he's", "her", "here", "here's", 
    "hers", "herself", "him", "himself", "his", "how", "how's", "howsoever", "i", "i", 
    "i'd", "i'll", "i'm", "i've", "if", "if not", "in", "into", "is", "is", 
    "isn't", "isn't", "it", "it'd", "it'll", "it's", "its", "itself", "know", "let", 
    "let's", "love", "me", "mine", "more", "moreover", "most", "most", "my", "myself", 
    "need", "needn't", "no", "nor", "not", "of", "off", "on", "once", "only", 
    "or", "other", "ought", "oughtn't", "our", "ours", "ourselves", "out", "over", "own", 
    "same", "she", "she'd", "she'll", "she's", "should", "shouldn't", "so", "so", "some", 
    "somebody", "someone", "such", "than", "that", "that", "that'd", "that'd", "that'll", "that'll", 
    "that's", "there", "there'd", "there's", "therefore", "these", "they", "they'd", "they'll", "they're", 
    "they've", "this", "this", "this's", "those", "through", "to", "together", "too", "under", 
    "until", "up", "very", "was", "wasn't", "we", "we", "we'd", "we'll", "we're", 
    "we've", "what", "what's", "whatsoever", "which", "which's", "who", "who's", "whoever", "whom", 
    "whomever", "why", "why ever", "why's", "with", "without", "would", "wouldn't", "yet", "you", 
    "you know", "you'd", "you'll", "you're", "you've", "your", "your", "yours", "yourself", "yourselves",
};

/* Most used top spanish words, sorted alphabetically */
static unsigned int dict_spa_length = 200;
static char *dict_spa[] = {
    "a", "aquí", "ahí", "al", "algo", "alguien", "algún", "allí", "ambos", "ante", 
    "antes", "aquel", "aquella", "aquellas", "aquello", "aquellos", "aquí", "así", 
    "aún", "aunque", "bajo", "bien", "cada", "casi", "como", "con", "contra", 
    "cual", "cuales", "cualquier", "cualquiera", "cuando", "cuanto", "cuantos", 
    "de", "debe", "debido", "decir", "del", "demás", "después", "desde", "donde", 
    "dos", "el", "ella", "ellas", "ello", "ellos", "en", "encima", "entonces", 
    "entre", "era", "eran", "es", "esa", "esas", "ese", "eso", "esos", "esta", 
    "estaba", "estado", "están", "estar", "estas", "este", "esto", "estos", 
    "estoy", "fue", "fuera", "fueron", "gran", "ha", "haber", "había", "habían", 
    "hace", "hacen", "hacer", "hacia", "han", "hasta", "hay", "he", "hecho", 
    "hemos", "hoy", "hubiera", "hubo", "igual", "incluso", "la", "las", "le", 
    "les", "lo", "los", "luego", "más", "me", "menos", "mi", "mientras", "mis", 
    "mismo", "misma", "mismas", "mismos", "mucho", "muy", "nada", "ni", "ningún", 
    "no", "nos", "nosotros", "nuestra", "nuestras", "nuestro", "nuestros", "o", 
    "otra", "otras", "otro", "otros", "para", "pero", "poco", "por", "porque", 
    "primero", "puede", "pueden", "pues", "qué", "que", "quedó", "querer", 
    "quién", "quienes", "quiere", "saber", "se", "sea", "sean", "según", "ser", 
    "si", "sí", "sido", "siempre", "sin", "sino", "sobre", "sois", "solamente", 
    "solo", "somos", "son", "soy", "su", "sus", "tal", "también", "tampoco", 
    "tan", "tanto", "te", "tendrá", "tendrán", "tenemos", "tener", "tengo", 
    "tenía", "tiempo", "tiene", "tienen", "toda", "todas", "todo", "todos", 
    "trabajo", "tras", "tú", "tu", "tus", "un", "una", "unas", "uno", "unos", 
    "usted", "ustedes", "va", "vamos", "van", "varios", "veces", "ver", "vez", 
    "vosotros", "voy", "ya", "yo"
};
    
/* Most used top german words, sorted alphabetically */
static unsigned int dict_ger_length = 200;
static char *dict_ger[] = {
    "aber", "ab", "alle", "alles", "als", "also", "am", "an", "andere", "andern", 
    "anfangen", "antworten", "arbeiten", "auch", "auf", "aus", "aussehen", 
    "bald", "bei", "beide", "beim", "beispiel", "bekommen", "besser", "beste", 
    "bis", "bitte", "bleiben", "brauchen", "bringen", "böse", "da", "damit", 
    "dann", "darauf", "darf", "dass", "davon", "dazu", "dein", "den", "denn", 
    "der", "deren", "dessen", "die", "dies", "dieser", "dir", "doch", "dort", 
    "du", "durch", "ein", "eine", "einem", "einen", "einer", "eines", "einfach", 
    "einige", "einmal", "er", "erst", "erwarten", "erzählen", "es", "essen", 
    "etwas", "euch", "euer", "fahren", "fallen", "fangen", "fast", "finden", 
    "fragen", "frau", "frei", "freund", "für", "gab", "ganz", "geben", "gefallen", 
    "gehen", "gehören", "genau", "gerade", "gern", "geschehen", "gibt", "gleich", 
    "gott", "groß", "gut", "haben", "halten", "hand", "hart", "hast", "hat", 
    "hatte", "haus", "heiß", "heißen", "her", "heraus", "hier", "hin", "hinten", 
    "hoch", "holen", "ich", "ihm", "ihn", "ihr", "ihre", "ihrem", "ihren", "ihres", 
    "im", "immer", "in", "ins", "ist", "ja", "jahr", "jeden", "jeder", "jedes", 
    "jetzt", "jung", "kann", "kein", "keine", "keiner", "kommen", "können", 
    "lassen", "laufen", "leben", "leicht", "leider", "lernen", "lesen", "letzt", 
    "liebe", "liegen", "machen", "man", "manchmal", "mann", "mehr", "mein", 
    "meine", "meinem", "meinen", "meiner", "meines", "mensch", "mit", "möchte", 
    "mögen", "möglich", "morgen", "müssen", "nach", "nachdem", "nah", "name", 
    "nehmen", "nicht", "nichts", "nie", "niemand", "noch", "nun", "nur", "ob", 
    "oder", "oft", "ohne", "recht", "rufen", "sagen", "sehen", "sein", "seine", 
    "seinem", "seinen", "seiner", "seines", "selbst", "setzen", "sich", "sie", 
    "sind", "so", "sogar", "soll", "sollen", "sondern", "sonst", "sprechen", 
    "stehen", "stellen", "stimme", "stunde", "tag", "tage", "tun", "über", 
    "um", "und", "unser", "unter", "verstehen", "viel", "vielleicht", "vor", 
    "wahr", "wann", "war", "wäre", "waren", "warum", "was", "weg", "weil", 
    "weiter", "welt", "wenig", "wenn", "wer", "werden", "wieder", "will", 
    "wir", "wird", "wissen", "wo", "wohl", "wollen", "wunderbar", "würde", 
    "würden", "zahlen", "zeit", "zu", "zufrieden", "zum", "zur", "zusammen"
};

/* Most used top italian words, sorted alphabetically */
static unsigned int dict_ita_length = 200;
static char *dict_ita[] = {
    "a", "abbiamo", "ad", "agli", "ai", "al", "alla", "alle", "allo", "anche", 
    "ancora", "anni", "anno", "anticipo", "appena", "avanti", "avere", "avete", 
    "aveva", "avevano", "avevo", "basta", "bene", "benissimo", "casa", "ce", 
    "chi", "ci", "cio", "cioe", "come", "comunque", "con", "cosa", "cosi", "da", 
    "dagli", "dai", "dal", "dalla", "dalle", "dallo", "de", "degli", "dei", "del", 
    "della", "delle", "dello", "dentro", "di", "dice", "dico", "dopo", "due", 
    "e", "ecco", "ed", "era", "erano", "essere", "fa", "faccio", "fare", "fatto", 
    "forse", "fra", "fuori", "gia", "gli", "ha", "hai", "hanno", "ho", "il", 
    "in", "indietro", "infatti", "insieme", "io", "la", "lavoro", "le", "lei", 
    "li", "lo", "loro", "lui", "ma", "mai", "me", "meno", "mentre", "mi", "mia", 
    "mie", "miei", "mio", "molto", "ne", "nei", "nel", "nella", "nelle", "nello", 
    "nessuno", "noi", "non", "nostra", "nostre", "nostri", "nostro", "o", "oggi", 
    "ogni", "ora", "per", "perche", "pero", "persone", "piace", "piu", "po", 
    "poi", "possa", "posso", "prendere", "presso", "prima", "proprio", "quale", 
    "qualunque", "quando", "quanti", "quanto", "qua", "quasi", "quella", "quelle", 
    "quelli", "quello", "questa", "queste", "questi", "questo", "qui", "quindi", 
    "sa", "sai", "sanno", "sapere", "sarà", "saro", "se", "sei", "sempre", "senza", 
    "sia", "siamo", "siete", "solo", "sono", "sopra", "sta", "stai", "stanno", 
    "stata", "state", "stati", "stato", "stessa", "stesso", "su", "subito", "sul", 
    "sulla", "sulle", "sullo", "tanto", "te", "tempo", "ti", "tra", "tre", 
    "troppo", "tu", "tua", "tue", "tuo", "tutti", "tutto", "un", "una", "uno", 
    "va", "vanno", "vedere", "vedo", "verso", "via", "vi", "voi", "volta", "volte"
};

/* Most used top french words, sorted alphabetically */
static unsigned int dict_fra_length = 200;
static char *dict_fra[] = {
    "à", "afin", "ai", "aie", "aient", "ainsi", "alla", "allait", "allant", 
    "allez", "allo", "allons", "après", "as", "assez", "au", "aucun", 
    "aucune", "aujourd'hui", "auquel", "aura", "aurai", "auraient", 
    "aurais", "aurait", "auras", "aurez", "auriez", "aurions", "aurons", 
    "auront", "autre", "autres", "aux", "avaient", "avais", "avait", 
    "avant", "avec", "avez", "aviez", "avions", "avoir", "avons", "ayant", 
    "ayez", "ayons", "ça", "car", "ce", "ceci", "cela", "celle", "celle-ci", 
    "celle-là", "celles", "celles-ci", "celles-là", "celui", "celui-ci", 
    "celui-là", "cent", "cependant", "certain", "certaine", "certaines", 
    "certains", "ces", "cet", "cette", "ceux", "ceux-ci", "ceux-là", 
    "chacun", "chacune", "chaque", "cher", "chère", "chez", "ci", "combien", 
    "comme", "comment", "compris", "concernant", "contre", "c'était", 
    "c'est", "d'", "da", "dans", "de", "dehors", "delà", "depuis", "derrière", 
    "des", "dès", "désormais", "desquels", "desquelles", "dessous", "dessus", 
    "deux", "devant", "devez", "deviez", "devions", "devons", "devoir", 
    "dois", "doit", "donc", "dont", "du", "durant", "e", "elle", "elles", 
    "en", "encore", "enfin", "entre", "envers", "es", "est", "et", "étaient", 
    "étais", "était", "étant", "étiez", "étions", "été", "être", "eu", 
    "eue", "eues", "euh", "eus", "eusse", "eussent", "eusses", "eussiez", 
    "eussions", "eut", "eux", "fais", "faisaient", "faisant", "faisons", 
    "fait", "faudra", "faudrait", "faut", "ferai", "feraient", "ferais", 
    "ferait", "fera", "feras", "ferez", "feriez", "ferions", "ferons", 
    "feront", "fi", "font", "furent", "fus", "fusse", "fussent", "fusses", 
    "fussiez", "fussions", "fut", "g", "grâce", "h", "hein", "hors", "i", 
    "ici", "il", "ils", "j'", "je", "jusqu'", "juste", "l'", "la", "là", 
    "laquelle", "le", "lequel", "les", "lesquels", "lesquelles", "leur", 
    "leurs", "lui", "l'un", "l'une", "ma", "mais", "malgré", "me", "même", 
    "mes", "mien", "mienne", "miennes", "miens", "moi", "moins", "mon", 
    "moyennant", "n'", "ne", "ni", "non", "nos", "notre", "nous", "nul", 
    "o", "où", "on", "ont", "ou", "ouh", "ouias", "oui", "outre", "p", 
    "par", "parce", "parfois", "parle", "parlent", "parler", "parlez", 
    "parmi", "parole", "pas", "personne", "peu", "peut", "peux", "pff", 
    "pfft", "pfut", "pif", "pire", "plouf", "plus", "plusieurs", "plutôt", 
    "pouah", "pour", "pourquoi", "premier", "près", "pu", "puis", "puisque", 
    "qu'", "quand", "quant", "quarante", "quatorze", "quatre", "quatre-vingt", 
    "que", "quel", "quelle", "quelles", "quelqu'un", "quelque", "quelques", 
    "quels", "qui", "quiconque", "quinze", "quoi", "rien", "s'", "sa", 
    "sans", "sauf", "se", "sera", "seraient", "serais", "serait", "seras", 
    "serez", "seriez", "serions", "serons", "seront", "ses", "seulement", 
    "si", "sien", "sienne", "siennes", "siens", "sinon", "soi", "soient", 
    "sois", "soit", "sommes", "son", "sont", "sous", "soyez", "soyons", 
    "suis", "suivant", "sur", "t'", "ta", "tandis", "te", "tel", "telle", 
    "telles", "tels", "tes", "toi", "ton", "toujours", "tous", "tout", 
    "toute", "toutes", "trois", "tu", "un", "une", "va", "vais", "vas", 
    "vers", "via", "voici", "voilà", "voir", "vos", "votre", "vous", 
    "zut"
};

static struct langdict_item_s local_dicts[] = {
    { LANG_ENGLISH, &dict_eng_length, dict_eng,  0, 0, 0, 0 },
    { LANG_SPANISH, &dict_spa_length, dict_spa,  0, 0, 0, 0 },
    { LANG_GERMAN,  &dict_ger_length, dict_ger,  0, 0, 0, 0 },
    { LANG_ITALIAN, &dict_ita_length, dict_ita,  0, 0, 0, 0 },
    { LANG_FRENCH,  &dict_fra_length, dict_fra,  0, 0, 0, 0 },
    { LANG_UNDEFINED, 0, 0, 0, 0, 0, 0 }
};

static struct langdict_item_s *getDictionary(struct langdict_context_s *ctx, enum langdict_type_e langtype)
{
    struct langdict_item_s *e = NULL, *i = &ctx->dicts[0];
    while (i->langtype != LANG_UNDEFINED) {
        if (i->langtype == langtype) {
            e = i;
            break;
        }
        i++;
    }
    if (!e) {
        return NULL;
    }

    return e;
}

static void resetDictionaries(struct langdict_context_s *ctx)
{
    struct langdict_item_s *e = &ctx->dicts[0];
    while (e->langtype != LANG_UNDEFINED) {
        e->total_failed_lookups  = 0;
        e->total_success_lookups = 0;
        e->total_found_words = 0;
        e->time_last_found = 0;
        e->time_last_search = 0;
        e++;
    }
}

static int compare_strings(const void *a, const void *b)
{
    const char *str1 = *(const char **)a;
    const char *str2 = *(const char **)b;
    return strcmp(str1, str2);
}

int langdict_alloc(void **handle)
{
    /* Sort all the dictionaries, ensure alphabetical order */
    int i = 0;
    while (local_dicts[i].langtype != LANG_UNDEFINED) {
        qsort(local_dicts[i].dict, *local_dicts[i].dict_length, sizeof(const char *), compare_strings);
        i++;
    }

    struct langdict_context_s *ctx = (struct langdict_context_s *)calloc(1, sizeof(*ctx));
    if (!ctx) {
        return -ENOMEM;
    }

    ctx->dicts = malloc(sizeof(local_dicts));
    if (!ctx->dicts) {
        free(ctx);
        return -ENOMEM;
    }
    memcpy(ctx->dicts, local_dicts, sizeof(local_dicts));

    langdict_stats_reset(ctx);

    *handle = ctx;

    return 0; /* Success */
}

void langdict_free(void *handle)
{
    struct langdict_context_s *ctx = (struct langdict_context_s *)handle;
    free(ctx->dicts);
    free(ctx);
}

void langdict_stats_reset(void *handle)
{
    struct langdict_context_s *ctx = (struct langdict_context_s *)handle;
    if (handle) {
        resetDictionaries(ctx);
    }
}

int langdict_stats_get_lookup_failed(void *handle, enum langdict_type_e langtype)
{
    struct langdict_context_s *ctx = (struct langdict_context_s *)handle;
    if (!handle) {
        return -EINVAL;
    }

    struct langdict_item_s *di = getDictionary(ctx, langtype);
    if (!di) {
        return -EINVAL;
    }

    return di->total_failed_lookups;
}

int langdict_stats_get_lookup_success(void *handle, enum langdict_type_e langtype)
{
    struct langdict_context_s *ctx = (struct langdict_context_s *)handle;
    if (!handle) {
        return -EINVAL;
    }

    struct langdict_item_s *di = getDictionary(ctx, langtype);
    if (!di) {
        return -EINVAL;
    }

    return di->total_success_lookups;
}

int langdict_stats_get_lookup_total(void *handle, enum langdict_type_e langtype)
{
    struct langdict_context_s *ctx = (struct langdict_context_s *)handle;
    if (!handle) {
        return -EINVAL;
    }

    struct langdict_item_s *di = getDictionary(ctx, langtype);
    if (!di) {
        return -EINVAL;
    }

    return di->total_found_words;
}

time_t langdict_stats_time_last_parse(void *handle, enum langdict_type_e langtype)
{
    struct langdict_context_s *ctx = (struct langdict_context_s *)handle;
    if (!handle) {
        return -EINVAL;
    }

    struct langdict_item_s *di = getDictionary(ctx, langtype);
    if (!di) {
        return -EINVAL;
    }

    return di->time_last_search;
}

time_t langdict_stats_time_last_word(void *handle, enum langdict_type_e langtype)
{
    struct langdict_context_s *ctx = (struct langdict_context_s *)handle;
    if (!handle) {
        return -EINVAL;
    }

    struct langdict_item_s *di = getDictionary(ctx, langtype);
    if (!di) {
        return -EINVAL;
    }

    return di->time_last_found;
}

int langdict_parse_dict(struct langdict_context_s *ctx, struct langdict_item_s *di,
    const char *dstr, int lengthBytes, time_t now)
{
    di->time_last_search = now;

    /* strtok manges the dstr, make a quick copy else we'll
     * under parse for second and subsequent language parses
     */
    char *display = strdup(dstr);

    char *psav = NULL;
    const char *t = strtok_r(display, " ,", &psav);
    while (t) {
        di->total_found_words++;

#if LOCAL_DEBUG
        printf("t: %20s '%c'  ", t, t[0]);
#endif
        /* Lookup the token in the dict, quick optimize search */
        int found = 0;
        int begin = 0;

        /* Start the search either at the beginning or middle */
        if (t[0] >= di->dict[*di->dict_length / 2][0]) {
            begin = (*di->dict_length / 2) - 1;
        }
        for (unsigned int i = begin; i < *di->dict_length; i++) {
            if (strcasecmp(di->dict[i], t) == 0) {
                found++;
                di->time_last_found = now;
            }
        }
        if (found) {
            di->total_success_lookups++;
#if LOCAL_DEBUG
            printf("    found\n");
#endif
        } else {
            di->total_failed_lookups++;
#if LOCAL_DEBUG
            printf("not found\n");
#endif
        }

        t = strtok_r(NULL, " ,.", &psav);
    };
    free(display);
    return 0;
}

int langdict_parse(void *handle, const char *display, int lengthBytes)
{
    if (!handle || !display || lengthBytes < 1) {
        return -EINVAL;
    }

    time_t now = time(NULL);

    struct langdict_context_s *ctx = (struct langdict_context_s *)handle;

    int updatets = 0;
    struct langdict_item_s *di = &local_dicts[0];

    while (di->langtype != LANG_UNDEFINED) {
        struct langdict_item_s *e = getDictionary(ctx, di->langtype);
        updatets += langdict_parse_dict(ctx, e, display, lengthBytes, now);
        di++;
    }

    return 0;
}

int langdict_get_stats(void *handle, enum langdict_type_e langtype, struct langdict_stats_s *stats)
{
    struct langdict_context_s *ctx = (struct langdict_context_s *)handle;
    if (!ctx || !stats) {
        return -EINVAL;
    }

    struct langdict_item_s *di = getDictionary(ctx, langtype);
    if (!di) {
        return -EINVAL;
    }

    stats->lang = langtype;
    stats->found = di->total_success_lookups;
    stats->missing = di->total_failed_lookups;
    stats->processed = di->total_found_words;
    stats->time_last_found = di->time_last_found;
    stats->time_last_search = di->time_last_search;

    stats->accuracypct = 0;
    if (di->total_found_words && di->total_success_lookups) {
        stats->accuracypct = ((float)di->total_success_lookups / (float)di->total_found_words) * 100.0;
    }

    return 0; /* success */
}

static void arrayify_dict(struct langdict_item_s *di)
{
    for (unsigned int i = 0; i < *di->dict_length; i++) {
        printf("\"%s\", ", di->dict[i]);
        if (i % 10 == 9)
            printf("\n");
    }
    printf("\n");
}

/* Private method I use to help prep the dictionary source code */
int langdict_sort_dict(enum langdict_type_e langtype)
{
    int i = 0;
    struct langdict_item_s *di = &local_dicts[i];

    while (di->langtype != LANG_UNDEFINED) {
        if (di->langtype == langtype) {
            qsort(di->dict, *di->dict_length, sizeof(const char *), compare_strings);
            arrayify_dict(di);
            break;
        }
        di++;
    }

    return 0;
}
