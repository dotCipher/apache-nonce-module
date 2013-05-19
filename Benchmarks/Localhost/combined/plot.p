#output as png image
set terminal png

#save file to "domain.png"
set output "pageload_benchmark.png"

#graph title
set title "Page Load Times"

#nicer aspect ratio for image size
set size 1,0.7

# y-axis grid
set grid y

#x-axis label
set xlabel "Number of Requests"

#y-axis label
set ylabel "Response Time (ms)"

#plot data from "domain.dat" using column 9 with smooth sbezier lines
#and title of "something" for the given data
plot "woNonce.dat" using 9 smooth sbezier with lines title "Module Disabled", \
"wNonce.dat" using 9 smooth sbezier with lines title "Module Enabled"
