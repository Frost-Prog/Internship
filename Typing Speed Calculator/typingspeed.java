import java.time.LocalTime;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;
import java.util.Timer;
import java.util.TimerTask;

public class typingspeed {
	static int m=0, n=0, l=0, o=0;	
	//create an array to store the sentences which we will use to display for evaluating the speed.
	static String[] story = {"when they are very young and much smaller we use the same size rope to tie them and, at that age, it’s enough to hold them. As they grow up, they are conditioned to believe they cannot break away. They believe the rope can still hold them, so they never try to break free.",
			          "Oh, how clumsy of me. Never mind, if you look into the bag for the one that is left, you will be able to tell which pebble I picked.",
			          "Your Honor, long before the baker started buying butter from me, I have been buying a pound loaf of bread from him. Every day when the baker brings the bread, I put it on the scale and give him the same weight in butter. If anyone is to be blamed, it is the baker.",
			          "You have done well, my son, but look at the holes in the fence. The fence will never be the same. When you say things in anger, they leave a scar just like this one. You can put a knife in a man and draw it out. It won’t matter how many times you say I’m sorry, the wound is still there.",
			          "I don’t want you to give him to me. That little dog is worth every bit as much as all the other dogs and I’ll pay full price. In fact, I’ll give you $2.37 now, and 50 cents a month until I have him paid for.",
			          "There was a man who had four sons. He wanted his sons to learn to not judge things too quickly. So he sent them each on a quest, in turn, to go and look at a pear tree that was a great distance away.",
			          "An elderly carpenter was ready to retire. He told his employer-contractor of his plans to leave the house-building business to live a more leisurely life with his wife and enjoy his extended family. He would miss the paycheck each week, but he wanted to retire. They could get by.",
			          "Once a group of 50 people were attending a seminar. Suddenly the speaker stopped and decided to do a group activity. He started giving each attendee one balloon. Each one was asked to write his/her name on it using a marker pen.",
			          "Once a young man asked the wise man, Socrates,  the secret to success. Socrates patiently listened to the man’s question and told him to meet him near the river the next morning for the answer. The next morning Socrates asked the young man to walk with him towards the river.",
			          "It was one of the coldest winter and many animals were dying because of the cold. The porcupines, realizing the situation, decided to group together to keep each other warm. This was a great way to protect themselves from cold and keep each of them warm"};

	public static void main(String[] args) throws InterruptedException {
		TimerTask task = new TimerTask() {
			public void run() {
					System.out.println( "time out" );
	                System.exit( 0 );
		}
	};
		//this displays the message that says the user to be ready for typing.
		System.out.println("Be Ready");
		//this creates a pause of 1 second
		TimeUnit.SECONDS.sleep(1);
		//prints 3 2 1 with a pause of 1 second.
		System.out.println("3");
		TimeUnit.SECONDS.sleep(1);
		
		System.out.println("2");
		TimeUnit.SECONDS.sleep(1);
		
		System.out.println("1");
		TimeUnit.SECONDS.sleep(1);
		//Creates a new random number generator
		Random rand = new Random();
		//stores one of the element in the array story into an array named as randnum
		String randnum = story[rand.nextInt(9)];
		System.out.println(randnum);
		//Splits this string around matches of the given regular expression.
		//We do this to break the Element of the array randnum so as to compare our input with each word in the element from the splt array.
		String[] splt=randnum.split(" ");
		//System.out.println(Arrays.toString(splt));
		
		System.out.println();
		
		//to calculate the time spent by the user to type the displayed sentence.
		double start = LocalTime.now().toNanoOfDay();
		
		Scanner read = new Scanner(System.in);
		Timer timer = new Timer();
		timer.schedule(task, 120*1000);
		
        System.out.println( "Type the displayed sentence, Time limit 2 minutes" );
		String input = read.nextLine();
	    
        timer.cancel();
		double end = LocalTime.now().toNanoOfDay();	
	    
		//calculate the duration
		double elapsedtime = end - start;
	    double seconds = elapsedtime / 1000000000.0;
	    
	    //we split the input stream and store that in an another array.
	    String[] inputarray = input.split(" ");
	    
	    //this denotes the number of elements in the array input and stores that in variable numchr. 
	    int numchr = input.length();
	    
	    //formula to calculate the number of words per minute.
	    //wpm=((All the typed  / 5)time(in seconds))
	    int wpm = (int) ((((double) numchr / 5) / seconds) * 60);
	    
	    //prints the typing speed in words per minute. 
	    System.out.println("Your typing speed in Words per minute is: " +wpm+"wpm");
	    
	    //this to  check if everything matches with displayed sentence then only this prints
	    if(randnum.equals(input)) {
	    	System.out.println("Perfect Score!!!!");
	    }
	    else {
	    	System.out.println("OOP's you made some mistakes.");
	    }
	    
	    //comparing the elements of both Input and given String which were converted in array are.
	    for (int e=0; e<inputarray.length; e++) {
	    		if(splt[e].equals(inputarray[e])) {
	    			//m is used here to calculate the number of correct words typed by the user.
	    			m=m+1;
	    			}
				else {
					//n is used here to calculate number of incorrect words typed by the user.
					n=n+1;
					}
	    }
	    /*Java does integer division, which basically is the same as regular real division,
		but you throw away the remainder (or fraction). That's why we use double. for type casting.*/
	    //we are using a variable called accuracy to calculate Accuracy of the characters typed in percentage.
	    double accuracy = ((m / (double) splt.length)*100);
	    System.out.println("The precision of the user in typing the words is: "+accuracy);
		//System.out.println(input.length());
	    
	    System.out.println("The number of correct words typed are: "+m);
		System.out.println("The number of incorrect words typed are: "+n);
		System.out.println("The number of missed words are: "+(splt.length - inputarray.length) +" out of " +splt.length);
		/*We calculate characters per minute by multiplying the 
		wpm with 5 as we consider there are average 5 character in a word*/
		System.out.println("Character per minute is: "+wpm * 5);
		
		/*we now want to check the accuracy of the characters typed
		so we split the words to individual characters.*/
		String[] inputchararray = input.split("");
		String[] givenchararray = randnum.split("");
		
		/*using for loop and if-else statements to compare the characters of the
		 * input string with that of the characters of displayed string.*/
		for(int i=0; i<inputchararray.length; i++) {
				if(inputchararray[i].equals(givenchararray[i])) {
					//l is used here to calculate the number of correct characters typed by the user.
					l = l + 1;
				}
				else {
					//o is used here to calculate the number of correct words typed by the user.
					o = o+1;
				}
			}
		System.out.println("The number of correct characters typed are: "+l);
		System.out.println("The number of incorrect characters typed are: "+o);
		System.out.println("The number of missed characters are: "+(givenchararray.length - inputchararray.length) +" out of "+givenchararray.length);
		//we are using a variable called acccuracy to calculate Accuracy of the characters typed in percentage.
		double acccuracy = ((l / (double) givenchararray.length)*100);
		System.out.println("The precision of the user in typing the characters is: "+acccuracy);
		
		//comments on the basis of user score.
		int j = (int)(double)accuracy;
		if((j >= 0) && (j <= 33)) {
			System.out.println("Better Luck Next time!");
			}
		else if((j > 33) && (j <= 66)) {
			System.out.println("Well Try, You can do better.");
		}
		else if ((j > 66) && (j <= 90)) {
			System.out.println("Awesome!!, You were really close.");
		}
		else if ((j > 90) && (j <= 100)) {
			System.out.println("Fantastic!!, You Nailed it.");
		}
	}
}