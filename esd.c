#include <stdio.h>
#include <LPC17xx.h>

#define RS_CTRL 0x08000000
#define ES_CTRL 0x10000000
#define DT_CTRL 0x07800000

unsigned char init_command[]={0x30,0x30,0x30,0x20,0x28,0x0c,0x01,0x80};

Unsigned char msg[]={‘Hello My name is Parzival’};
Unsigned long int temp1=0,temp2=0;
Unsigned long int flag1=0,flag2=0;

Void lcd_write()
{
	flag2=(flag1==1)?0:((temp1==0x30)||(temp1==0x20))?1:0;
	temp2=temp1 & 0xF0;
	temp2=temp1<<19;
	port_write()
	if(!flag2)
	{
		temp2=temp1 & 0x0F;
		temp2=temp2<<23;
		port_write();
	}
} 
Void port_write()
{
	LPC_GPIO0->FIOPIN=temp2;
	if(flag1==0)//flag1=0->command argument
	{
		LPC_GPIO0->FIOCLR=RS_CTRL;
	}
	else
	{
		LPC_GPIO0->FIOSET=RS_CTRL;
	}
	LPC_GPIO0->FIOSET=EN_CTRL;
	delay(500);
	LPC_GPIO0->FIOCLR=EN_CTRL;
	delay(50000);
}
Void delay(unsigned long int r1)
{
	unsigned long int r;
	for(r=0;r<r1;r++);
}

Void main()
{
	LPC_PINCON->PINSEL=0;
	LPC_GPIO0->FIODIR=RS_CTRL|EN_CTRL|DT_CTRL;
	flag1=0;
	int I;
	for(I=0;i<8;i++)
	{
		temp1=init_command[I];
		lcd_write();
	}
	flag1=1;
	I=0;
	while(msg!=‘\0’)
	{
		if(col==16)
		{
			flag1=0;
			temp1=0xC0;
			lcd_write();
			flag1=1;
		}
		else if(col==32)
		{
			flag1=0;
			temp1=0x80;
			lcd_write;
			flag1=1;
			col=0;
		}
		temp1=msg[I++];
		lcd_write();
		col++;
		
	}
	
while(1);

}

********************************************************************************
#include <stdio.h>
#include <LPC17xx.h>

Unsigned char hex_seg[4][4]={0x3F,0x06,0x5B,0x4F,0x66,0x6D,0x7D,0x07,0x7F,0x6F,0x77,0x7c,0x58,0x5C,0x79,0x71};
Unsigned long int seg[]={0xFFF87FFF,0xFFF8FFFF,0xFFF97FFF,0xFFF9FFFF};
Unsigned int col;
Unsigned int temp1=0,flag=0;

Void scan()
{
	unsigned int temp1=0;
	temp1=LPC_GPIO1->FIOPIN;
	if(temp1!=0x00000000)
	{
		flag=1;
		if(temp1 & 1<<23)
		{
			col=0;
		}
		else if(temp1 & 1<<24)
		{
			col=1;
		}
		else if(temp1 & 1<<25)
		{
			col=2;
		}
		else if(temp1 & 1<<26)
		{
			col=3;
		}
	}
}
Void main()
{
	LPC_PINCON->PINSEL0=0;
	LPC_PINCON->PINSEL1=0;
	LPC_PINCON->PINSEL3=0;
	LPC_PINCON->PINSEL4=0;
	LPC_GPIO0->FIODIR=0xFFFFFFFF;
	LPC_GPIO1->FIODIR=0x0<<23;
	LPC_GPIO2->FIODIR=0xF<<10;
	while(1)
	{
		for(row=0;row<4;row++)
		{
			if(row==0)
			{
				temp=1<<10;
			}
			else if(row==1)
			{
				temp=1<<11;
			}
			else if(row==2)
			{
				temp=1<<12;
			}
			else if(row==3)
			{
				temp=1<<13;
			}
			LPC_GPIO2->FIOPIN=temp;
			flag=0;
			scan();
			if(flag==1)
			{
				LPC_GPIO0->FIOMASK=0xFFF87FFF;
				LPC_GPIO0->FIOPIN=seg[row];
				LPC_GPIO0->FIOMASK=0xFFFFF00F;
				LPC_GPIO0->FIOPIN=hex_seg[row][col]<<4;
			}
		}
	}
}

********************************************************************************

#include <stdio.h>
#include <LPC17xx.h>

duty_cycle=0;
step=50;
direction=1;
Void PWM1_IRQHandler()
{
	if(LPC_PWM1->IR & 1<<0)
	{
		if(direction==1)
		{
			duty_cycle+=step;
			if(duty_cycle>=3000)
			{
				direction=0;
			}
		}
		else
		{
			duty_cycle-=step;
			if(duty_cycle==0)
			{
				direction=1;
			}
		}
		LPC_PWM1->MR4=duty_cycle;
		LPC_PWM1->LER=1<<4;
		LPC_PWM1->IR=1<<0;
	}
}
Void main()
{
	LPC_PINCON->PINSEL3=2<<14;
	LPC_PWM1->TCR=1<<1;
	LPC_PWM1->CTCR=0;
	LPC_PWM1->PR=0;
	LPC_PWM1->MR0=3000;
	LPC_PWM1->MR4=duty_cycle;
	LPC_PWM1->MCR=(1<<0)|(1<<1);
	LPC_PWM1->PCR=1<<12;
	LPC_PWM1->LER=(1<<0)|(1<<4);
	NVIC_EnableIRQ(PWM1_IRQn);
	LPC_PWM1->TCR=(1<<0)|(1<<3);
	while(1);
}

********************************************************************************
