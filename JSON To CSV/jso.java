package jso;

import java.util.Scanner;


//import jdk.internal.misc.FileSystemOption;

//import javax.swing.text.html.HTMLDocument.Iterator;

//import jdk.internal.misc.FileSystemOption;

//import com.sun.tools.javac.code.Attribute.Array;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
//import org.json.simple.JSONObject;    
//import org.json.simple.JSONValue;
//import org.json.simple.JSONArray;
//import org.json.simple.JSONObject;
//import org.json.simple.parser.JSONParser;
//import org.json.simple.parser.ParseException;
//import org.json.simple.*;
//import org.json.simple.parser.*;

public class jso {

	public static void main(String[] args) throws IOException {
		System.out.println("Please Select the option you want to use:\n1:To Convert CSV to JSON\n2:To Convert JSON to CSV");
		Scanner rem = new Scanner(System.in);
		int num = rem.nextInt();
		switch(num) {
		case 1:
			int t=1, p=0;
			Scanner rea = new Scanner(System.in);
			Scanner ren = new Scanner(System.in);
			System.out.println("Please Input the location where the File is located in your computer.\n");
			String input = rea.nextLine();
			System.out.println("Please Input the location where the Json file is to be saved.\n");
			String output = ren.nextLine();
			List<List<String>> records = new ArrayList<>();
			try (BufferedReader br = new BufferedReader(new FileReader(input))) {
			    String line;
			    while ((line = br.readLine()) != null) {
			        String[] values = line.split("[,]");
			        records.add(Arrays.asList(values));
			        System.out.println(Arrays.toString(values));
			    }
			}
			List<String> th= records.get(0);
			String k1= String.join(",", th);
			String k2= k1.replace("﻿","");
			String[] k3 = k2.split(",");
			System.out.println(Arrays.toString(k3));
			System.out.println(records.size());
			try {
			      File myObj = new File(output);
			      if (myObj.createNewFile()) {
			        System.out.println("File created: " + myObj.getName());
			      } else {
			        System.out.println("File already exists.");
			      }
			    } catch (IOException e) {
			      System.out.println("An error occurred.");
			      e.printStackTrace();
			    }
			try {
			      FileWriter myWriter = new FileWriter(output);
			      myWriter.write("[");
			while(t<records.size()) {
				List<String> t1= records.get(t);
				String t2= String.join(",", t1);
				String[] t3 = t2.split(",");
				myWriter.write(" {\n");
				for(p=0;p<k3.length-1;p++) {
					myWriter.write(" "+k3[p]+":"+t3[p]+",\n"
						);
					}
				myWriter.write(" "+k3[p]+":"+t3[p]+"\n");
				if(t==records.size()-1) {
					myWriter.write(" }\n");
				}
				else {
					myWriter.write(" },\n");
				}
				t++;
		    }
			myWriter.write("]");
			myWriter.close();
		      System.out.println("Successfully wrote to the file.");
		    } catch (IOException e) {
		      System.out.println("An error occurred.");
		      e.printStackTrace();
		    }
			break;
		case 2:
			System.out.println("Please Enter the location of the JSON file for input");
			Scanner res = new Scanner(System.in);
			String input1 = res.nextLine();
			System.out.println("Please Enter the location of the CSV file to be Saved");
			Scanner rek = new Scanner(System.in);
			String output1 = rek.nextLine();
			List<List<String>> recording = new ArrayList<>();
			try (BufferedReader br = new BufferedReader(new FileReader(input1))) {
			    String line;
			    while ((line = br.readLine()) != null) {
			    	String[] values = line.split("[:]");
			    	if (values[0].equals("[ {") || values[0].equals(" {") || values[0].equals("]") || values[0].equals(" },") || values[0].equals("}]") || values[0].equals(" }")) {
			    	}
			    	else {
			    		recording.add(Arrays.asList(values));
			    		//System.out.println(Arrays.toString(values));	
			    	}
			    }
			}
			    //System.out.println(recording);
			try {
			      File myObj = new File(output1);
			      if (myObj.createNewFile()) {
			        System.out.println("File created: " + myObj.getName());
			      } else {
			        System.out.println("File already exists.");
			      }
			    } catch (IOException e) {
			      System.out.println("An error occurred.");
			      e.printStackTrace();
			    }
			try {
			      //FileWriter myWritten = new FileWriter(output1);
			      System.out.println(recording.size());
			      int w=0;
			      List<String> q2 = recording.get(0);
			      String q3 = q2.get(0);
			      System.out.println(q3);
			      for(List<String> g1: recording) {
			    	  for(String o1: g1){
			    		  if(q3.equals(o1)) {
			    			  w=w+1;
			    		  }
			    	  }
			      }
			      System.out.println(w);
			      int c = recording.size() / w;
			      int q21 = 0, q22 = 0, e1 = 0, v = 0;
			      List<String> k223= new ArrayList<>();
			      while(q21 < c) {
			    	  List<String> l = recording.get(q21);
			    	  String h1 = l.get(0);
			    	  String h11 = h1.replace(",","");
			    	  String h111 = h11.replaceFirst(" ","");
			    	  String h1111 = h111.replaceAll("^\"+|\"+$", "");
			    	  String h11111 = h1111.strip();
			    	  System.out.println(h11111);
			    	  k223.add(h11111);
			    	  q21+=1;
			    	  System.out.println(q21);
			      }
			      System.out.println(k223);
			      StringBuilder sb = new StringBuilder();
			      int i = 0;
			        while (i < k223.size() - 1)
			        {
			            sb.append(k223.get(i));
			            sb.append(",");
			            i++;
			        }
			        sb.append(k223.get(i));
			        FileWriter myWrote = new FileWriter(output1);
			        String res1 = sb.toString();
			        System.out.println(res1);
			        myWrote.write(res1+"\n");
			        //myWrote.close();
			        System.out.println("done");
			
			               
			 int q221=0;
			 int e=0;
			 int s = c;
			while(e < w) {
				List<String> k224= new ArrayList<>();
				while(q221 < c) {
					List<String> l = recording.get(q221);
			    	  String h1 = l.get(1);
			    	  String h11 = h1.replace(",","");
			    	  String h111 = h11.replaceFirst(" ","");
			    	  String h1111 = h111.replaceAll("^\"+|\"+$", "");
			    	  String h11111 = h1111.strip();
			    	  //System.out.println(h11111);
			    	  k224.add(h11111);
			    	  q221+=1;
				}
		      //System.out.println(k224);
		      StringBuilder sb1 = new StringBuilder();
		      int a = 0;
		        while (a < k224.size() - 1)
		        {
		            sb1.append(k224.get(a));
		            sb1.append(",");
		            a++;
		        }
		        sb1.append(k224.get(a));
		        String res11 = sb1.toString();
		        System.out.println(res11);
		        myWrote.write(res11+"\n");
				e=+1;
				c=c+s;
				if(q221 == recording.size()) {
					break;
				}
			}
			myWrote.close();
			System.out.println("Data has been Successfully Written to File.");
			}
			catch (IOException e) {
			      System.out.println(e);
		      }
		break;
		default:
	    	System.out.println("Please Enter a valid input.");
}	
}
}