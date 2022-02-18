//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

package org.car2x.veins.modules.application.DDos;
import org.car2x.veins.modules.application.ieee80211p.DemoBaseApplLayer;

simple DDos extends DemoBaseApplLayer
{
    parameters:
        @class(veins::DDos);
        @display("i=block/app2");
    
        double time_window = default(2s) @unit(s);
        double attack_pausibility = default(0.8);
        double starttime = default(0s) @unit(s);
        double DDosInterval = default(0.01s) @unit(s);
        double IncreasingRate = default(0.95);
        double IncreasingType = default(1);
        double Increaseingthreshold = default(0.05);
        int num_of_groups = default(2);
        double duration = default(5s) @unit(s);                      //On-Off Attack, the duration of a turn
        
        int DDosType = default(0);                                   //0: Normal
                                                                     //1: Constant rate 
                                                                     //2: Increasing rate 
                                                                     //3: On-Off attack
                                                                     //4: Pulse-increasing
                                                                     
        int MsgType = default(3);                                    //0: Normal
                                                                     //1: Speed
                                                                     //2: Position
                                                                     //3: Heading
                                                                     //4: Mix
        double attackerSpeedRangeMin = default(-5);
        double attackerSpeedRangeMax = default(5);
        double attackerPosRangeMin = default(-5);
        double attackerPosRangeMax = default(5);
//        double attackerAcclRangeMin = default(-5);
//        double attackerAcclRangeMax = default(5);
        double attackerHeadRangeMin = default(-5);
        double attackerHeadRangeMax = default(5);
}