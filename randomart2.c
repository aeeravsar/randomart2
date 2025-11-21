#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

/* Simple SHA256 implementation */
#define SHA256_BLOCK_SIZE 32

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;

#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static const uint32_t k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    for ( ; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len) {
    uint32_t i;

    for (i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

void sha256_final(SHA256_CTX *ctx, uint8_t hash[]) {
    uint32_t i;

    i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56)
            ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64)
            ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i) {
        hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
    }
}

void generate_randomart(const char *seed, int height, int width, int num_walkers, int show_title) {
    SHA256_CTX ctx;
    uint8_t hash[SHA256_BLOCK_SIZE];
    int **field;
    int *x_pos, *y_pos, *start_x, *start_y, *end_x, *end_y;
    int i, j, bit_pair, walker;
    uint8_t byte, direction;
    int dx, dy;
    const char *chars = " .o+=*BOX@%&#/^";
    int chars_len = strlen(chars);
    char walker_seed[4096];

    /* Allocate field dynamically */
    field = malloc(height * sizeof(int*));
    for (i = 0; i < height; i++) {
        field[i] = calloc(width, sizeof(int));
    }

    /* Allocate walker tracking arrays */
    x_pos = malloc(num_walkers * sizeof(int));
    y_pos = malloc(num_walkers * sizeof(int));
    start_x = malloc(num_walkers * sizeof(int));
    start_y = malloc(num_walkers * sizeof(int));
    end_x = malloc(num_walkers * sizeof(int));
    end_y = malloc(num_walkers * sizeof(int));

    /* Process each walker */
    for (walker = 0; walker < num_walkers; walker++) {
        /* Create unique seed for each walker */
        snprintf(walker_seed, sizeof(walker_seed), "%s:%d", seed, walker);

        /* Compute SHA256 hash of walker seed */
        sha256_init(&ctx);
        sha256_update(&ctx, (uint8_t*)walker_seed, strlen(walker_seed));
        sha256_final(&ctx, hash);

        /* Start at center */
        x_pos[walker] = width / 2;
        y_pos[walker] = height / 2;
        start_x[walker] = x_pos[walker];
        start_y[walker] = y_pos[walker];

        /* Process each byte of hash */
        for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
            byte = hash[i];
            /* Each byte gives us 4 moves (2 bits per move) */
            for (bit_pair = 0; bit_pair < 4; bit_pair++) {
                direction = (byte >> (bit_pair * 2)) & 0b11;

                /* Move based on direction: 00=NW, 01=NE, 10=SW, 11=SE */
                dx = (direction & 0b01) ? 1 : -1;
                dy = (direction & 0b10) ? 1 : -1;

                /* Update position with boundary checking */
                x_pos[walker] += dx;
                y_pos[walker] += dy;
                if (x_pos[walker] < 0) x_pos[walker] = 0;
                if (x_pos[walker] >= width) x_pos[walker] = width - 1;
                if (y_pos[walker] < 0) y_pos[walker] = 0;
                if (y_pos[walker] >= height) y_pos[walker] = height - 1;

                /* Increment visit count */
                field[y_pos[walker]][x_pos[walker]]++;
            }
        }

        end_x[walker] = x_pos[walker];
        end_y[walker] = y_pos[walker];
    }

    /* Print title if requested */
    if (show_title) {
        int seed_len = strlen(seed);
        int padding = (width - seed_len) / 2;

        printf("+");
        for (i = 0; i < width; i++) printf("-");
        printf("+\n|");

        /* Center the seed text */
        if (seed_len <= width) {
            for (i = 0; i < padding; i++) printf(" ");
            printf("%s", seed);
            for (i = padding + seed_len; i < width; i++) printf(" ");
        } else {
            /* Truncate if too long */
            for (i = 0; i < width; i++) {
                printf("%c", seed[i]);
            }
        }
        printf("|\n");
    }

    /* Print top border */
    printf("+");
    for (i = 0; i < width; i++) printf("-");
    printf("+\n");

    /* Print field */
    for (i = 0; i < height; i++) {
        printf("|");
        for (j = 0; j < width; j++) {
            int is_start = 0, is_end = 0;

            /* Check if any walker starts or ends here */
            for (walker = 0; walker < num_walkers; walker++) {
                if (i == start_y[walker] && j == start_x[walker]) is_start = 1;
                if (i == end_y[walker] && j == end_x[walker]) is_end = 1;
            }

            if (is_start) {
                printf("S");
            } else if (is_end) {
                printf("E");
            } else {
                int idx = field[i][j];
                if (idx >= chars_len) idx = chars_len - 1;
                printf("%c", chars[idx]);
            }
        }
        printf("|\n");
    }

    /* Print bottom border */
    printf("+");
    for (i = 0; i < width; i++) printf("-");
    printf("+\n");

    /* Free allocated memory */
    for (i = 0; i < height; i++) {
        free(field[i]);
    }
    free(field);
    free(x_pos);
    free(y_pos);
    free(start_x);
    free(start_y);
    free(end_x);
    free(end_y);
}

void usage(const char *progname) {
    fprintf(stderr, "Usage: %s [-w WIDTH] [-h HEIGHT] [-n NUM_WALKERS] [-t] [seed]\n", progname);
    fprintf(stderr, "  -w WIDTH        Canvas width (default: 17)\n");
    fprintf(stderr, "  -h HEIGHT       Canvas height (default: 9)\n");
    fprintf(stderr, "  -n NUM_WALKERS  Number of walkers/objects (default: 1)\n");
    fprintf(stderr, "  -t              Show seed as title above the art\n");
    fprintf(stderr, "  seed            Seed string (if not provided, reads from stdin)\n");
    exit(1);
}

int main(int argc, char *argv[]) {
    int width = 17;
    int height = 9;
    int num_walkers = 1;
    int show_title = 0;
    int opt;

    /* Parse command-line options */
    while ((opt = getopt(argc, argv, "w:h:n:t")) != -1) {
        switch (opt) {
            case 'w':
                width = atoi(optarg);
                if (width <= 0) {
                    fprintf(stderr, "Error: width must be positive\n");
                    usage(argv[0]);
                }
                break;
            case 'h':
                height = atoi(optarg);
                if (height <= 0) {
                    fprintf(stderr, "Error: height must be positive\n");
                    usage(argv[0]);
                }
                break;
            case 'n':
                num_walkers = atoi(optarg);
                if (num_walkers <= 0) {
                    fprintf(stderr, "Error: num_walkers must be positive\n");
                    usage(argv[0]);
                }
                break;
            case 't':
                show_title = 1;
                break;
            default:
                usage(argv[0]);
        }
    }

    /* Check for seed argument after options */
    if (optind < argc) {
        /* Concatenate remaining args as seed */
        char seed[4096] = "";
        int i;
        for (i = optind; i < argc; i++) {
            if (i > optind) strcat(seed, " ");
            strcat(seed, argv[i]);
        }
        generate_randomart(seed, height, width, num_walkers, show_title);
    } else {
        /* No argument: read from stdin */
        char line[4096];
        while (fgets(line, sizeof(line), stdin)) {
            /* Remove newline */
            line[strcspn(line, "\n\r")] = '\0';
            generate_randomart(line, height, width, num_walkers, show_title);
            printf("\n");
        }
    }

    return 0;
}
