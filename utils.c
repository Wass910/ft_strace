#include "syscall.h"

double calc_pourcent(double valeur, double total) {
    double pourcentage = (valeur / total) * 100;
    return pourcentage;
}

void	ft_lstadd_back(t_summary **alst, t_summary *new)
{
	t_summary	*lst;

	lst = *alst;
	if (*alst == NULL)
		*alst = new;
	else
	{
		while (lst->next)
			lst = lst->next;
		lst->next = new;
	}
}

t_summary	*ft_fill_summary(int nb, int error, int sys, long long time)
{
	t_summary	*lst = malloc(sizeof(t_summary));

	lst->arch = 0;
	lst->number_of_calls = nb;
	lst->error = error;
	lst->syscall =sys;
	lst->usecond = time;
	lst->next = NULL;
	return lst;
}

int	check_summary(int sys, int error)
{
	t_summary *tmp = g_summary;
	int i = 0;
	while(tmp)
	{
		if (tmp->syscall == sys){
			tmp->number_of_calls++;
		if (error == 1)
			tmp->error = tmp->error + 1;
		return 1;
		}
		tmp = tmp->next;
		i++;
	}
	return 0;
}

long long time_in_microseconds(struct timeval start_time, struct timeval end_time) {
    long long start_in_microseconds = start_time.tv_sec * 1000000LL + start_time.tv_usec;
    long long end_in_microseconds = end_time.tv_sec * 1000000LL + end_time.tv_usec;
    return end_in_microseconds - start_in_microseconds;
}

double microseconds_to_seconds(long long microseconds) {
    return (double)microseconds / 1000000.0;
}

double	calc_time()
{
	t_summary *tmp = g_summary;
	int i = 0;
	double time_total = 0;
	while(tmp)
	{
		tmp->seconds = microseconds_to_seconds(tmp->usecond) * tmp->number_of_calls ;
		time_total = time_total + tmp->seconds;
		tmp = tmp->next;
		i++;
	}
	return time_total;
}
