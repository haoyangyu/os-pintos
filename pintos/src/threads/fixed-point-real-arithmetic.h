//
//  fixed-point-real-arithmetic.h
//  practice
//
//  Created by HY on 3/18/15.
//  Copyright (c) 2015 HY. All rights reserved.
//

#ifndef practice_fixed_point_real_arithmetic_h
#define practice_fixed_point_real_arithmetic_h

#define q 14
#define f (1<<q)

typedef int realValue;

realValue fixed_point_init(int, int);
realValue fixed_point_multiply(realValue, realValue);
realValue fixed_point_divide(realValue, realValue);
int fixed_point_round_zero(realValue);
int fixed_point_round_nearest(realValue);

/*Initialize the realValue, which means that mapping the real number into 32bit format*/
realValue fixed_point_init(realValue n, realValue denom){
	return (n*f)/denom;
}

/*fixed_point_multiply*/
realValue fixed_point_multiply(realValue x, realValue y){
	return ((int64_t)x)*y/f;
}

realValue fixed_point_divide(realValue x, realValue y){
	return ((int64_t)x)*f/y;
}

int fixed_point_round_zero(realValue x){
	return x/f;
}

int fixed_point_round_nearest(realValue x){
	if(x>=0){
		return (x+f/2)/f;
	}else{
		return (x-f/2)/f;
	}
}



#endif
