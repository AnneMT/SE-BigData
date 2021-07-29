"""
 Security Enhanced Big Data
 Big Data Security Analyzer
   Finite State Machine used to analyze probable attacks 
   and probable security service control defenses to
   produce modeled downtime.
 Source point of contact - Anne Tall
 Date = 29 June 2021
 
"""
# Import libraries(Standard, Third party, Local application/library)

import sys
import os
import csv
import pprint
import uuid
from random import seed
from random import randint

import xlsxwriter
import xlrd
from xlrd import open_workbook
import openpyxl
import pandas as pd
import numpy

from scipy.stats import poisson
from scipy.stats import binom

from transitions import Machine
import random
from random import seed
import datetime
from datetime import datetime
from datetime import timedelta

import matplotlib
from matplotlib import pyplot as plt
from matplotlib.font_manager import FontProperties
plt.interactive(True)

# Define Constants

DAYS_MODELED = 365
NUM_RUNS = 5
ATTACK_PERIOD = 365
MODELS = ["Model_A", "Model_B", "Model_C", "Model_D", "Model_E"]

# Paths and reference files
localFilePath = "c:\\Users\\Anne_2\\Documents\\UCF\\MILCOM-Paper\\Python"  #File path for
# Excel Spreadsheet data files that are input to the program
#
#Workbooks
excelInputWbk = "input-control-attack.xls" #input reference data Excel Workbook
excelDataWbk = "data-control-attack.xls" #data mapping security service controls and attacks Excel Workbook
#
#Worksheets in Workbooks
ControlMechWks = "CostModel"  # The Worksheet in the Input Excel Workbook
# which lists the mechnamisms that provide the security service controls

# Constants associated with the system and data value that influence the motivation of the attacker
# Zero (0) is low and Five (5) is high
SYSTEM_DATA_VALUE = 2 #overall threshold value that the data and system have value between 0 and 5
DNS = 1 # likelihood of an attacker being motivated based upon DNS name, between 0 and 5
BUS_TYPE = 1 # likelihood of an attacker being motivated based upon Business Type, between 0 and 5
POL_CLIM = 0 # likelihood of an attacker being motivated based upon Political Climate, between 0 and 5
MED_ATT = 0 # likelihood of aof an attacker being motivated based upon Media Attention, between 0 and 5

#Overall likelihood of an attack is between 1 and 5 
#The overall value is based the technical likelihood (first value) and impact (second value) 
ATTACK_PROB = {(1,1): 1, (1,2): 2, (1,3): 1, (1,4): 2, (1,5): 2, (2,1): 1, (2,2): 2, (2,3): 2, (2,4): 2, (2,5):3, \
            (3,1): 1, (3,2): 2, (3,3): 3, (3,4): 3, (3,5): 4, (4,1): 1, (4,2): 2, (4,3): 3, (4,4): 4, (4,5): 5, \
            (5,1): 1, (5,2): 2, (5,3): 3, (5,4): 4, (5,5): 5}

#THRESHOLD_SECURITY = 1 # overall control success likelihood between 0 and 10

# Seed the random value generator
# using the current microsecond time 
now = datetime.now()
microseed = now.microsecond
random.seed (microseed) 


# Define Class to hold attacker - sercurity service control data from the spreadsheet
class SpreadsheetData(object):
    def __init__(self, row_num=[], control_ID=[], control_name=[], technique_ID=[], technique_name=[], applicable=[],\
    control_impl_prob=[], control_main_prob=[],\
    attack_prob=[], impact_prob=[], avg_mitigation=[], avg_recover_time=[]):
        self.row_num = row_num
        self.control_ID = control_ID
        self.control_name = control_name
        self.technique_ID = technique_ID
        self.technique_name = technique_name
        self.applicable = applicable
        self.control_impl_prob = control_impl_prob
        self.control_main_prob = control_main_prob
        self.attack_prob = attack_prob
        self.impact_prob = impact_prob
        self.avg_mitigation = avg_mitigation
        self.avg_recover_time = avg_recover_time

    def __str__(self):
        return ("row_num  = {0} \t"
        "  control_ID  = {1} \t" 
        "  control_name  = {2} \t" 
        "  technique_ID  = {3} \t" 
        "  technique_name  = {4} \t" 
        "  applicable  = {5} \t" 
        "  control_impl_prob  = {6} \t" 
        "  control_main_prob  = {7} \t" 
        "  control_cost  = {8} \t" 
        "  control_maint_cost  = {9} \t" 
        "  control_fund  = {10} \t" 
        "  attack_prob  = {11} \t" 
        "  impact_prob  = {12} \t"
        "  avg_mitigation   = {13} \t"
        "  avg_recover_time  = {14}"
        .format(self.row_num, self.control_ID, self.control_name, self.technique_ID, self.technique_name, \
            self.applicable, self.control_impl_prob, self.control_main_prob, self.control_cost, self.control_maint_cost, \
            self.control_fund, self.attack_prob, self.impact_prob, self.avg_mitigation, self.avg_recover_time))

        __repr__ = __str__ #support printing out the entire class

class SpreadsheetControls(object):
    def __init__(self, mechanism=[], control_IDs=[], cost_aqu=[], cost_main=[], model_A_impl=[], model_A_main=[],\
    model_B_impl=[], model_B_main=[], model_C_impl=[], model_C_main=[], model_D_impl=[], model_D_main=[],\
    model_E_impl=[], model_E_main=[]):
        self.mechanism = mechanism
        self.control_IDs = control_IDs
        self.cost_aqu = cost_aqu
        self.cost_main = cost_main
        self.model_A_impl = model_A_impl
        self.model_A_main = model_A_main
        self.model_B_impl = model_B_impl
        self.model_B_main = model_B_main
        self.model_C_impl = model_C_impl
        self.model_C_main = model_C_main
        self.model_D_impl = model_D_impl
        self.model_D_main = model_D_main
        self.model_E_impl = model_E_impl
        self.model_E_main = model_E_main

    def __str__(self):
        return ("mechanism  = {0} \t"
        "  control_IDs  = {1} \t" 
        "  cost_aqu  = {2} \t" 
        "  cost_main  = {3} \t" 
        "  model_A_impl  = {4} \t" 
        "  model_A_main  = {5} \t" 
        "  model_B_impl  = {6} \t" 
        "  model_B_main  = {7} \t" 
        "  model_C_impl  = {8} \t" 
        "  model_C_main  = {9} \t"
        "  model_D_impl  = {10} \t"
        "  model_D_main  = {11} \t"
        "  model_E_impl = {12} \t"
        "  model_E_main = {13} \t"
        .format(self.mechanism, self.control_IDs, self.cost_aqu, self.cost_main,\
            self.model_A_impl, self.model_A_main, self.model_B_impl, self.model_B_main,\
            self.model_C_impl, self.model_C_main, self.model_D_impl, self.model_D_main,\
            self.model_E_impl, self.model_E_main))

        __repr__ = __str__ #support printing out the entire class

class PlotData(object):
    def __init__(self, model=[], run_num=[], degradation=[], degraded_num=[], down_time=[], total_cost=[]):
        self.model = model
        self.run_num = run_num
        self.degradation = degradation
        self.degraded_num = degraded_num
        self.down_time = down_time
        self.total_cost = total_cost

    def __str__(self):
        return ("model  = {0} \t"
        "  run_num  = {1} \t" 
        "  degradation  = {2} \t"
        "  degraded_num = {3} \t" 
        "  down_time  = {4} \t" 
        "  total_cost  = {5}" 
        .format(self.model, self.run_num, self.degradation, self.degraded_num, self.down_time, self.total_cost))

        __repr__ = __str__ #support printing out the entire class


# Define Finite State Machine Class
class SecurityStateMachine(object):

    # Defined 5 states. Cybersecurity attackers when active can launch attacks,
    # these attacks are sometimes twarted by security serivces, 
    # when a compromise does occurr, the system is in a degraded state and may need to be recovered
    states = ['operating', 'attacking', 'protecting', 'degraded', 'recovery']

    def __init__(self):

        # Initialize the state machine
        self.machine = Machine(model=self, states=SecurityStateMachine.states, initial='operating')

        # Lists used in the machine
        self.control_success = []
        self.control_restore = []
        self.control_damage = []
        self.control_fails = []

        # Transition Definitions. 

        # The active attacker needs to be motivated to launch an attack, 
        # otherwise the attacker is paused in the same state
        self.machine.add_transition(trigger='motivated', source='operating', dest='attacking') 
        self.machine.add_transition(trigger='running', source ='operating', dest = 'operating')

        # Attacks are launched based upon the technical complexity, potential mission impact, 
        # this corresponds to the resulting red/yellow/green importance from Cyber Table Top
        self.machine.add_transition('attack_attempted','attacking','protecting') 
        self.machine.add_transition('failed', 'attacking', 'operating') ## no attacks launched

        # Security services provide protection against launched attacks
        # however the security services are not always succesful
        # misconfigured, out of date software, and well crafted attacks can result is attack success
        self.machine.add_transition('attack_success', 'protecting', 'degraded')
        self.machine.add_transition('thwarted', 'protecting', 'operating')

        # The degraded system may be be restored or damaged based upon the severity of the attack
        # The time required for recovery is tracked after the last state.
        self.machine.add_transition('restored', 'degraded', 'operating') 
        self.machine.add_transition('damaged', 'degraded', 'recovery')
        self.machine.add_transition('mitigating', 'degraded', 'degraded')

        # Repair and Recovery from being degraded
        # A succesful attack and security service failure preceed a degraded state
        # The time for recovery is added as down-time.
        self.machine.add_transition('repaired', 'recovery', 'operating')
        self.machine.add_transition('recovering', 'recovery', 'recovery') 

    @property
    def is_motivated(self):
        """ Based upon value of the assest and environmental conditions """
        global SYSTEM_DATA_VALUE, DNS, BUS_TYPE, POL_CLIM, MED_ATT
        data_value = (float(SYSTEM_DATA_VALUE) / 5.0)
        
        environ_condit = (float(DNS)/5.0) + (float(BUS_TYPE)/5.0) + (float(POL_CLIM)/5.0) + (float(MED_ATT)/5.0)
        
        prob_motivated = data_value + environ_condit
        p=prob_motivated
        n=1
        random_var_motivated = binom.rvs(n, p, size=1)

        if (random_var_motivated > 0):
            motivation_result = True
        else:
            motivation_result = False
        return motivation_result

    def attacks_launched(self, input_spreadsheet=[]):
        """ read each attack type and associated probabilities from a spreasheet """
        """ return the attack_type list based upon the computed random variable of success """
        global ATTACK_PROB
        global ATTACK_PERIOD
        attack_types = []
        attack_launch_selected = False
            
        for item in input_spreadsheet:
            
            values_attack =[]
            line_attack=[]

            n = (int(item.attack_prob)) 
            m = (int(item.impact_prob))
            tup = (n,m) 
            prob_attack = ATTACK_PROB[tup]
            #print ("probability of attack = ", prob_attack)
            p=(float(prob_attack)/5.0)/ATTACK_PERIOD  #divide the probability by the attack period variable
            n=1
            random_var_attack = numpy.round(binom.rvs(n, p, size=1))

            if (random_var_attack > 0):
                values_attack = (item.row_num, item.control_ID, item.control_name, item.technique_ID, \
                item.technique_name, item.applicable, item.control_impl_prob, item.control_main_prob, \
                item.attack_prob, item.impact_prob, item.avg_mitigation, item.avg_recover_time)

                line_attack = SpreadsheetData(*values_attack)
                attack_types.append(line_attack)

                attack_launch_selected = True # at least one attack probability listed in the spreadsheet
                                              # is successfully launched based upon binomial distributed variate              
        
        return attack_launch_selected, attack_types

    def controls_protect(self, input_attacks=[]):
        """ read the corresponding security serivce control and its probabilities of success """
        """ for each attack_type from a spreasheet """
        """ return the list of failed  """
        """ security service control based upon the computed random variable """
        security_service_control_fails = []
        thwarted = True
            
        for item in input_attacks:
            thwarted = True
            values_controls =[]
            line_controls=[]

            p1 = (float(int(item.control_impl_prob)))/5.0  # FIX - Need to handle blank values 
            p2 = (float(int(item.control_main_prob)))/5.0
            p = p1 * p2 # AND condition - security service implemented and maintained
            n=1
            control_likelihood = (binom.rvs(n, p, size=1)) # One Binomial Distributed Number generated 
            
            if ((item.applicable == 'y') and (control_likelihood == 0)):
                values_control = (item.row_num, item.control_ID, item.control_name, item.technique_ID, \
                item.technique_name, item.applicable, item.control_impl_prob, item.control_main_prob, \
                item.attack_prob, item.impact_prob, item.avg_mitigation, item.avg_recover_time)

                line_control = SpreadsheetData(*values_control)
                security_service_control_fails.append(line_control)

                thwarted = False   # at least one control protection probability listed in the spreadsheet
                                   # has failed    

        return thwarted, security_service_control_fails #, security_service_control_success

    def  detect_recover(self, control_fails_in=[]):
        """ read proability of detection and recovery """ 
        """ for each attack success or security_service_control_fails """
        """ from spreadsheet """
        """ compute likelihood of recovery or damage"""
        recovery_required = []
        restore = True
        degraded_value_total=0
        degraded_val_sum=0
        max_degraded_value=0
        num=0

        for item in control_fails_in:
            num = num+1
            values_recovery =[]
            line_recovery=[]

            detect_prob = ((((6.0 - float(item.attack_prob)) + (6.0 - float(item.impact_prob)))/ATTACK_PERIOD) + \
                float(item.control_impl_prob))/3.0
            p = (float(detect_prob))/5.0
            
            
            n=1
            random_var_recovery = (binom.rvs(n, p, size=1))  # One Binomial Distributed Number generated 
            
            if (random_var_recovery == 0):
                values_recovery = (item.row_num, item.control_ID, item.control_name, item.technique_ID, \
                item.technique_name, item.applicable, item.control_impl_prob, item.control_main_prob, \
                item.attack_prob, item.impact_prob, item.avg_mitigation, item.avg_recover_time)

                line_recovery = SpreadsheetData(*values_recovery)
                recovery_required.append(line_recovery)

                restore = False   # at least one retore from attack based upon probability listed in the spreadsheet
                                   # is required
            else:
                mean = int(item.avg_mitigation)
                degraded_value = poisson.rvs(mu=mean, size=1) # Poisson distributed variate
                
                #degraded_value_total = degraded_value + degraded_value_total # use an average of the degraded values plus amplification
                degraded_val_sum = degraded_val_sum + degraded_value
                if (degraded_value > max_degraded_value):
                    max_degraded_value = numpy.round(degraded_value)
        if (num <=100):  #10
            degraded_val_score = 0
        elif (num <= 500): #50
            degraded_val_score = 0.25 #1 #0.25
        elif (num <= 1000): #100
            degraded_val_score = 0.5 #2 #0.5
        elif (num <= 2000): #175
            degraded_val_score = 0.75 #3 #0.75
        else:
            degraded_val_score = 1 #4 #1
        avg_degraded_val = round((float(degraded_val_sum)) / float(num))
        amp_deg_value = round(degraded_val_score * avg_degraded_val)
        degraded_value_total = max_degraded_value + amp_deg_value
        return restore, degraded_value_total, recovery_required 

    def add_down_time(self, recovery_required_in=[]):
        """ increase the down time based upon the down time/severity of """
        """ the failed security services against the launched attacks """
        """ as listed in the spreadsheet """

        down_time_sum = 0
        num = 0
        max_down_time = 0
            
        for item in recovery_required_in:
            num = num+1
            mean = int(item.avg_recover_time)
            down_time_rand = poisson.rvs(mu=mean, size=1) # Poisson distributed variate
            
            down_time_sum = down_time_sum + down_time_rand

            if (down_time_rand > max_down_time):
                max_down_time = numpy.round(down_time_rand)
        if (num <=100):  #10
            attack_vol_score = 0
        elif (num <= 500): #50
            attack_vol_score = 0.25 #1 #0.25
        elif (num <= 1000): #100
            attack_vol_score = 0.5 #2 #0.5
        elif (num <= 2000): #175
            attack_vol_score = 0.75 #3 #0.75
        else:
            attack_vol_score = 4 #4 #1
        avg_down_time = round((float(down_time_sum)) / float(num))
        amp_value = round(attack_vol_score * avg_down_time)
        down_time_output = max_down_time + amp_value
        return down_time_output

def computeTotalCost (model):
    wb = xlrd.open_workbook(excelInputWbk)
    sheet1 = wb.sheet_by_name(ControlMechWks)
    number_of_rows1 = sheet1.nrows #37
    number_of_columns1 = sheet1.ncols #14

    lines1 = []

    for row in range(1, number_of_rows1):
        values1 = []
        for col in range(0, number_of_columns1):
            value1  = (sheet1.cell(row, col).value)
            try:
                value1 = str(int(value1))
            except ValueError:
                value1 = 0 #pass
            finally:
                values1.append(value1)
            line1 = SpreadsheetControls(*values1)
        lines1.append(line1)
    
    sum_total = 0
    if (model == "Model_A"):
        for line1 in lines1:
            sum_one = (int(line1.cost_aqu) * int(line1.model_A_impl)) + (int(line1.cost_main) * int(line1.model_A_main))
            sum_total = sum_one + sum_total
    
    if (model == "Model_B"):
        for line1 in lines1:
            sum_one = (int(line1.cost_aqu) * int(line1.model_B_impl)) + (int(line1.cost_main) * int(line1.model_B_main))
            sum_total = sum_one + sum_total

    if (model == "Model_C"):
        for line1 in lines1:
            sum_one = (int(line1.cost_aqu) * int(line1.model_C_impl)) + (int(line1.cost_main) * int(line1.model_C_main))
            sum_total = sum_one + sum_total

    if (model == "Model_D"):
        for line1 in lines1:
            sum_one = (int(line1.cost_aqu) * int(line1.model_D_impl)) + (int(line1.cost_main) * int(line1.model_D_main))
            sum_total = sum_one + sum_total

    if (model == "Model_E"):
        for line1 in lines1:
            sum_one = (int(line1.cost_aqu) * int(line1.model_E_impl)) + (int(line1.cost_main) * int(line1.model_E_main))
            sum_total = sum_one + sum_total

    return sum_total

"""  Main Function   """

if __name__ == '__main__':

# open Spreadsheet and make a class of the attack - security service control data
    plot_data = []
    wb = xlrd.open_workbook(excelDataWbk)   
    
    ####
    ## First Loop - For Each Cost Model (A - E) 
    ####
    for model in MODELS:  # for each model type read values from spreadsheet
        down_time_total=0
        ModelWks = model

        sheet = wb.sheet_by_name(ModelWks)

        number_of_rows = sheet.nrows
        number_of_columns = sheet.ncols

        lines = []
        rows = []
        for row in range(1, number_of_rows):
            values = []
            for col in range(0, number_of_columns):
                value  = (sheet.cell(row,col).value)
                try:
                    value = str(int(value))
                except ValueError:
                    pass
                finally:
                    values.append(value)
            line = SpreadsheetData(*values)
            lines.append(line)
        
        ####
        ## Second Loop - Number of Runs - Run the State Machine the number of times for each model
        ####
        
        run_num = 0
        for run_num in range (0, NUM_RUNS): ## compute values for multiple runs of the same cost models
            run = SecurityStateMachine()
                        
            # The state machine runs for the number days modeled
            # then prints output the down days, 
            # based upon random attack and security service control effectivenss values,
            # multiple runs could be averaged to discern value
            x = DAYS_MODELED
            down_time_runs_total=0
            down_time=0
            down_time_total=0
            down_time_run=0
            degraded_total = 0
            degraded_num=0
            values = ()
            i=0

            ####
            # Third Loop - Number of Days Modeled
            ####
            while i < x :
                
                if (run.is_motivated == True):
                    run.motivated() # transition to attacking state
                    test_attacks, attacks_attempt = run.attacks_launched(lines)
                    
                    if (test_attacks == True):
                        run.attack_attempted() # transition to protecting state
                        test_controls, failed_controls = run.controls_protect(attacks_attempt)
                        
                        if (test_controls == True):
                            run.thwarted()  # transition to operating state
                            
                        else:
                            run.attack_success() # transition to degraded state
                            test_recover, degraded_value, recovery_required = run.detect_recover(failed_controls)

                            if (test_recover == True):
                                run.restored() # transition to operating state
                                degraded_total = degraded_value + degraded_total
                                degraded_num = degraded_num+1
                                i = i+1
                            else:
                                run.damaged() # transition to recovery state
                                down_time_run = int(run.add_down_time(recovery_required)) # down time in hours for all attacks in the run 

                                # step forward in time the number of days down
                                i = i + round(float(down_time_run)/24.0) # convert down time from hours to days - modify if different time unit used
                                down_time_total = down_time_run + down_time_total
                                down_time_run=0  

                                run.repaired() # transition to operating 
                                
                    else:
                        run.failed() #transition to operating state
                        i = i+1
                else:
                    run.running() # transtion (to same-state) operating
                    i = i+1
            
                # Save data from finite state machine execution for Cost Model in class
                          

            #end of Loop 3
            down_time_runs_total=down_time_total #+down_time_runs_total
            total_cost = computeTotalCost(ModelWks)
            
            values = (ModelWks, run_num, int(degraded_total), degraded_num, down_time_runs_total, total_cost)
            line_data = PlotData(*values)
            plot_data.append(line_data)

        #end of Loop 2
    #end of Loop 1

    #
    #PLOTS
    #
    fig, (ax1, ax2)=plt.subplots(nrows=2)
    #fig.subplots_adjust(left=0.2, wspace=0.6)

    # Plot Security Costs versus Down Time
    print ("Number of Days Modeled = ", DAYS_MODELED )
    y_axis1 = []
    y_axis2 = []
    y_axis3 = []
    y_axis4 = []
    y_axis5 = []
    x_axis1 = []
    x_axis2 = []
    x_axis3 = []
    x_axis4 = []
    x_axis5 = []
    for item in plot_data:
        print (item)
        if (item.model == 'Model_A'):
            y_axis1_val = int(float(item.down_time)/24.0) #convert down time from hours to days
            y_axis1.append(y_axis1_val)
            x_axis_val1 = int(item.total_cost)
            x_axis1.append(x_axis_val1)
        if (item.model == 'Model_B'):
            y_axis2_val = int(float(item.down_time)/24.0)
            y_axis2.append(y_axis2_val)
            x_axis_val2 = int(item.total_cost)
            x_axis2.append(x_axis_val2)
        if (item.model == 'Model_C'):
            y_axis3_val = int(float(item.down_time)/24.0)
            y_axis3.append(y_axis3_val)
            x_axis_val3 = int(item.total_cost)
            x_axis3.append(x_axis_val3)
        if (item.model == 'Model_D'):
            y_axis4_val = int(float(item.down_time)/24.0)
            y_axis4.append(y_axis4_val)
            x_axis_val4 = int(item.total_cost)
            x_axis4.append(x_axis_val4)
        if (item.model == 'Model_E'):
            y_axis5_val = int(float(item.down_time)/24.0)
            y_axis5.append(y_axis5_val)
            x_axis_val5 = int(item.total_cost)
            x_axis5.append(x_axis_val5)

    #plot1=plt.figure(1)
    ax1.scatter(x_axis1, y_axis1, marker='x', color='black', label='Model A')
    ax1.scatter(x_axis2, y_axis2, marker='s', color='red', label='Model B')    
    ax1.scatter(x_axis3, y_axis3, marker='^', color='blue', label='Model C')
    ax1.scatter(x_axis4, y_axis4, marker='o', color='green', label='Model D')
    ax1.scatter(x_axis5, y_axis5, marker='D', color='orange', label='Model E')

    #Chart Title and Lables

    ax1.set_title("Security Costs versus Down Time\n")
    ax1.set_xlabel ("Cost ($K)")
    ax1.set_ylabel ("Down-Time (days)")
    fontP = FontProperties()
    fontP.set_size('small')
    ax1.legend (loc='upper right', ncol=1, prop=fontP)
    ax1.grid(color='black', linestyle='--', linewidth=0.5)

    # Plot Security Costs versus Degradation
    
    y_axis11 = 0.0
    y_axis22 = 0.0
    y_axis33 = 0.0
    y_axis44 = 0.0
    y_axis55 = 0.0
    x_axis11 = 0.0
    x_axis22 = 0.0
    x_axis33 = 0.0
    x_axis44 = 0.0
    x_axis55 = 0.0
    sum_degraded_A=0
    sum_degraded_num_A=0
    sum_degraded_B=0
    sum_degraded_num_B=0
    sum_degraded_C=0
    sum_degraded_num_C=0
    sum_degraded_D=0
    sum_degraded_num_D=0
    sum_degraded_E=0
    sum_degraded_num_E=0
    
    for item in plot_data:
        
        if (item.model == 'Model_A'):
            sum_degraded_A = sum_degraded_A + item.degradation
            sum_degraded_num_A = sum_degraded_num_A + item.degraded_num
            x_axis11 = float(int(item.total_cost))
            
        if (item.model == 'Model_B'):
            sum_degraded_B = sum_degraded_B + item.degradation
            sum_degraded_num_B = sum_degraded_num_B + item.degraded_num
            x_axis22 = int(item.total_cost)

        if (item.model == 'Model_C'):
            sum_degraded_C = sum_degraded_C + item.degradation
            sum_degraded_num_C = sum_degraded_num_C + item.degraded_num
            x_axis33 = int(item.total_cost)

        if (item.model == 'Model_D'):
            sum_degraded_D = sum_degraded_D + item.degradation
            sum_degraded_num_D = sum_degraded_num_D + item.degraded_num
            x_axis44 = int(item.total_cost)

        if (item.model == 'Model_E'):
            sum_degraded_E = sum_degraded_E + item.degradation
            sum_degraded_num_E = sum_degraded_num_E + item.degraded_num
            x_axis55 = int(item.total_cost)

    if (sum_degraded_num_A>0):
        y_axis111 = float(sum_degraded_A) / sum_degraded_num_A
        y_axis11 = sum_degraded_A
    else:
        y_axis11=0.05
        y_axis111 =0
    if (sum_degraded_num_B>0):
        y_axis222 = float(sum_degraded_B) / sum_degraded_num_B
        y_axis22 = sum_degraded_B
    else:
        y_axis22=0.05
        y_axis222 =0
    if (sum_degraded_num_C>0):
        y_axis333 = float(sum_degraded_C) / sum_degraded_num_C
        y_axis33 = sum_degraded_num_C
    else:
        y_axis33=0.05
        y_axis333 =0
    if (sum_degraded_num_D>0):
        y_axis444 = float(sum_degraded_D) / sum_degraded_num_D
        y_axis44= sum_degraded_D
    else:
        y_axis44=0.05
        y_axis444 =0
    if (sum_degraded_num_E>0):
        y_axis555 = float(sum_degraded_E) / sum_degraded_num_E
        y_axis55 = sum_degraded_E
    else:
        y_axis55=0.05
        y_axis555 =0

    width = 100
    ax2.bar(x_axis11, y_axis11, width, color='black', label='Model A')
    ax2.bar(x_axis22, y_axis22, width, color='red', label='Model B')    
    ax2.bar(x_axis33, y_axis33, width, color='blue', label='Model C')
    ax2.bar(x_axis44, y_axis44, width, color='green', label='Model D')
    ax2.bar(x_axis55, y_axis55, width, color='orange', label='Model E')
    
    print ('Model A degraded number and average = ', sum_degraded_num_A, y_axis111)
    print ('Model B degraded number and average = ', sum_degraded_num_B, y_axis222)
    print ('Model C degraded number and average = ', sum_degraded_num_C, y_axis333)
    print ('Model D degraded number and average = ', sum_degraded_num_D, y_axis444)
    print ('Model E degraded number and average = ', sum_degraded_num_E, y_axis555)

    #Chart Title and Lables

    ax2.set_title("Security Costs versus Degradation\n")
    ax2.set_xlabel ("Cost ($K)")
    ax2.set_ylabel ("Degradation Total")
    fontP = FontProperties()
    fontP.set_size('small')
    ax2.legend (loc='upper right', ncol=1, prop=fontP)
    ax2.grid(color='black', linestyle='--', linewidth=0.5)

    plt.show ('500')