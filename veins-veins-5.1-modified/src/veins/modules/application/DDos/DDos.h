/*
 * DDos.h
 *
 *  Created on: 2021Äê9ÔÂ27ÈÕ
 *      Author: YF
 */

#pragma once

#include <string>
#include "veins/modules/application/ieee80211p/DemoBaseApplLayer.h"
#include "veins/base/utils/FindModule.h"
#include "veins/modules/application/DDos/DDosMessage_m.h"
#include "veins/modules/mobility/traci/TraCIMobility.h"

namespace veins
{
class DDos : public DemoBaseApplLayer {

public:
    virtual void initialize(int stage) override;

protected:
//**************************************
    std::string traceJSONFile_1;
    std::string traceJSONFile_2;
    std::string traceJSONFile_3;
    std::string traceJSONFile_4;
    std::string traceJSONFile_5;

    double time_window;
    double time_window_floor;
    int received_packets;
    int received_addresses;
    int max_pkt_from_sameId;
    bool has_attacker;

    double prepkt_time;
    double lastpkt_time;

    double IAT_Mean;
    double IAT_Std;
    double IAT_Max;
    double IAT_Min;

    LAddress::L2Type *addresses_stack;//received different addresses
    int *pktnum_stack;//number of packets from same address
    double *IAT_stack;
//**************************************
    LAddress::L2Type senderAddress = -1;
//    LAddress::L2Type victimAddress = 0;
//**************************************
    Heading heading;
//    double Acceleration;
//**************************************
    double attackerSpeedRangeMin;
    double attackerSpeedRangeMax;
    double attackerPosRangeMin;
    double attackerPosRangeMax;
//    double attackerAcclRangeMin;
//    double attackerAcclRangeMax;
    double attackerHeadRangeMin;
    double attackerHeadRangeMax;

//**************************************
//    LAddress::L2Type* vehiclesAddress;//It's not vehicles'addresses. It indicate weather a vehicle is a attacker
//    LAddress::L2Type* attackersAddress;

    simtime_t starttime;
    simtime_t DDosInterval;
    simtime_t newInterval;
    simtime_t duration;
    simtime_t timeleft;
    double IncreasingRate;
    int IncreasingType;
    double Increaseingthreshold;

    bool synchronous = false;//A flag used in pulse attack to synchronize time

    double seed;
//    int num_of_vehicles;
//    int num_of_attackers;
    double attack_pausibility;

    bool is_attacker;
    int DDostype_in_BSM;
    int Msgtype_in_BSM;

/*    enum DDosType
    {
        Constant,
        Increasing,
        Fluctuation
    };*/
    int ddostype;
    int msgtype;

    int num_of_groups;
    int group;
    enum Key{
        ON,
        OFF
    };

    Key key;

    virtual void populateWSM(BaseFrame1609_4* wsm, LAddress::L2Type rcvId = LAddress::L2BROADCAST(), int serial = 0) override;

    void RecordTrueData(DDosMessage* ddos);

    void handleSelfMsg(cMessage* msg) override;

    virtual void handlePositionUpdate(cObject* obj) override;

    void handleLowerMsg(cMessage* msg) override;

    void onDDos(DDosMessage* ddos);

    void ConstantRate(DDosMessage* ddos);
    void IncreasingRate1(DDosMessage* ddos);
    void IncreasingRate2(DDosMessage* ddos);
    void PulseAttack(DDosMessage* ddos);
    void Increasing_Pulse(DDosMessage* ddos);

    void SetRandomDynamicSpeed();
    void SetRandomDynamicPosition();
//    void SetRandomDynamicAcceleration();
    void SetRandomDynamicHeading();

    virtual const void traceJSON(std::string file, std::string JSONObject) const;
//    void FlectorAttack(BaseFrame1609_4* wsm, LAddress::L2Type rcvId = LAddress::L2BROADCAST(), int serial = 0);

};


}
