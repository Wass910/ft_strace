SRC=    srcs/itoa.c srcs/utils.c srcs/strace.c srcs/32_bits.c srcs/64_bits.c \

OBJS			= $(SRC:.c=.o)

NAME			= ft_strace

CFLAGS			= -Wall -Wextra -Werror 

RM				= rm -f

CC				= gcc

%.o : %.c
				$(CC) $(CFLAGS) -c $< -o $@

$(NAME):		$(OBJS)
				$(CC) $(CFLAGS) $(OBJS) -o $(NAME) -L.

all:			$(NAME)

clean:
				$(RM) $(OBJS) 

fclean:			clean
				$(RM) $(NAME)

re:				fclean all

.PHONY:			all clean fclean c.o re 